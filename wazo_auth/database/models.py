# Copyright 2017-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
    schema,
    sql,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship

Base = declarative_base()


class Address(Base):

    __tablename__ = 'auth_address'

    id_ = Column(Integer, name='id', primary_key=True)
    tenant_uuid = Column(
        String(38),
        ForeignKey('auth_tenant.uuid', ondelete='CASCADE'),
        nullable=False,
    )
    line_1 = Column(Text)
    line_2 = Column(Text)
    city = Column(Text)
    state = Column(Text)
    zip_code = Column(Text)
    country = Column(Text)


class Email(Base):

    __tablename__ = 'auth_email'

    uuid = Column(
        String(38), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    address = Column(Text, unique=True, nullable=False)
    confirmed = Column(Boolean, nullable=False, default=False)
    main = Column(Boolean, nullable=False, default=False)
    user_uuid = Column(
        String(38),
        ForeignKey('auth_user.uuid', ondelete='CASCADE'),
        nullable=False,
    )


class ExternalAuthConfig(Base):

    __tablename__ = 'auth_external_auth_config'

    tenant_uuid = Column(
        String(38), ForeignKey('auth_tenant.uuid', ondelete='CASCADE'), primary_key=True
    )
    type_uuid = Column(
        String(36),
        ForeignKey('auth_external_auth_type.uuid', ondelete='CASCADE'),
        primary_key=True,
    )
    data = Column(Text, nullable=False)


class ExternalAuthType(Base):

    __tablename__ = 'auth_external_auth_type'

    uuid = Column(
        String(38), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    name = Column(Text, unique=True, nullable=False)
    enabled = Column(Boolean, server_default='false')


class Group(Base):

    __tablename__ = 'auth_group'

    uuid = Column(
        String(38), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    name = Column(Text, unique=True, nullable=False)
    tenant_uuid = Column(
        String(38), ForeignKey('auth_tenant.uuid', ondelete='CASCADE'), nullable=False
    )
    system_managed = Column(
        Boolean, nullable=False, default=False, server_default='false'
    )


class GroupPolicy(Base):

    __tablename__ = 'auth_group_policy'

    policy_uuid = Column(
        String(38), ForeignKey('auth_policy.uuid', ondelete='CASCADE'), primary_key=True
    )
    group_uuid = Column(
        String(38), ForeignKey('auth_group.uuid', ondelete='CASCADE'), primary_key=True
    )


class Tenant(Base):

    __tablename__ = 'auth_tenant'

    uuid = Column(
        String(38), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    name = Column(Text)
    slug = Column(String(10), nullable=False, unique=True)
    phone = Column(Text)
    contact_uuid = Column(String(38), ForeignKey('auth_user.uuid', ondelete='SET NULL'))
    parent_uuid = Column(String(38), ForeignKey('auth_tenant.uuid'), nullable=False)


class Token(Base):

    __tablename__ = 'auth_token'
    __table_args__ = (Index('auth_token__idx__session_uuid', 'session_uuid'),)

    uuid = Column(
        String(38), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    session_uuid = Column(
        String(36), ForeignKey('auth_session.uuid', ondelete='CASCADE'), nullable=False
    )
    auth_id = Column(Text, nullable=False)
    pbx_user_uuid = Column(String(36))
    xivo_uuid = Column(String(38))
    issued_t = Column(Integer)
    expire_t = Column(Integer)
    metadata_ = Column(Text, name='metadata')
    user_agent = Column(Text)
    remote_addr = Column(Text)
    acl = Column(ARRAY(Text), nullable=False, server_default='{}')

    session = relationship('Session')


class RefreshToken(Base):

    __tablename__ = 'auth_refresh_token'
    __table_args__ = (UniqueConstraint('client_id', 'user_uuid'),)

    uuid = Column(
        String(36), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    client_id = Column(Text)
    user_uuid = Column(String(36), ForeignKey('auth_user.uuid', ondelete='CASCADE'))
    backend = Column(Text)
    login = Column(Text)
    user_agent = Column(Text)
    remote_addr = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=text('NOW()'))
    mobile = Column(Boolean, nullable=False, default=False)
    user = relationship('User', viewonly=True)

    @hybrid_property
    def tenant_uuid(self):
        return self.user.tenant_uuid

    @tenant_uuid.expression
    def tenant_uuid(cls):
        return (
            sql.select([User.tenant_uuid])
            .where(User.uuid == cls.user_uuid)
            .label('tenant_uuid')
        )


class Session(Base):

    __tablename__ = 'auth_session'

    uuid = Column(
        String(36), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    tenant_uuid = Column(
        String(38), ForeignKey('auth_tenant.uuid', ondelete='CASCADE'), nullable=False
    )
    mobile = Column(Boolean, nullable=False, default=False)

    tokens = relationship('Token', viewonly=True)


class Policy(Base):

    __tablename__ = 'auth_policy'
    __table_args__ = (
        UniqueConstraint('name', 'tenant_uuid'),
        Index('auth_policy__idx__slug', func.lower('slug'), 'tenant_uuid', unique=True),
    )

    uuid = Column(
        String(38), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    name = Column(String(80), nullable=False)
    slug = Column(String(80), nullable=False)
    description = Column(Text)
    tenant_uuid = Column(
        String(38), ForeignKey('auth_tenant.uuid', ondelete='CASCADE'), nullable=False
    )
    config_managed = Column(
        Boolean,
        default=False,
        server_default='false',
        nullable=True,
    )
    tenant = relationship('Tenant', cascade='all, delete-orphan', single_parent=True)
    accesses = relationship('Access', secondary='auth_policy_access', viewonly=True)

    @property
    def acl(self):
        return [access.access for access in self.accesses]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tenant_uuid_exposed = None
        self.read_only = None


class User(Base):

    __tablename__ = 'auth_user'

    uuid = Column(
        String(38), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    username = Column(String(256), unique=True, nullable=False)
    firstname = Column(Text)
    lastname = Column(Text)
    password_hash = Column(Text)
    password_salt = Column(LargeBinary)
    purpose = Column(
        Text,
        CheckConstraint("purpose in ('user', 'internal', 'external_api')"),
        nullable=False,
    )
    enabled = Column(Boolean)
    tenant_uuid = Column(
        String(38), ForeignKey('auth_tenant.uuid', ondelete='CASCADE'), nullable=False
    )

    emails = relationship('Email', viewonly=True)


class UserExternalAuth(Base):

    __tablename__ = 'auth_user_external_auth'
    __table_args__ = (schema.UniqueConstraint('user_uuid', 'external_auth_type_uuid'),)

    user_uuid = Column(
        String(38), ForeignKey('auth_user.uuid', ondelete='CASCADE'), primary_key=True
    )
    external_auth_type_uuid = Column(
        String(38),
        ForeignKey('auth_external_auth_type.uuid', ondelete='CASCADE'),
        primary_key=True,
    )
    data = Column(Text, nullable=False)


class UserGroup(Base):

    __tablename__ = 'auth_user_group'

    user_uuid = Column(
        String(38), ForeignKey('auth_user.uuid', ondelete='CASCADE'), primary_key=True
    )
    group_uuid = Column(
        String(38), ForeignKey('auth_group.uuid', ondelete='CASCADE'), primary_key=True
    )


class UserPolicy(Base):

    __tablename__ = 'auth_user_policy'

    user_uuid = Column(
        String(38), ForeignKey('auth_user.uuid', ondelete='CASCADE'), primary_key=True
    )
    policy_uuid = Column(
        String(38), ForeignKey('auth_policy.uuid', ondelete='CASCADE'), primary_key=True
    )


class Access(Base):

    __tablename__ = 'auth_access'
    __table_args__ = (UniqueConstraint('access'),)

    id_ = Column(Integer, name='id', primary_key=True)
    access = Column(Text, nullable=False)


class PolicyAccess(Base):

    __tablename__ = 'auth_policy_access'

    policy_uuid = Column(
        String(38), ForeignKey('auth_policy.uuid', ondelete='CASCADE'), primary_key=True
    )
    access_id = Column(
        Integer,
        ForeignKey('auth_access.id', ondelete='CASCADE'),
        primary_key=True,
    )
