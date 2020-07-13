# Copyright 2017-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    schema,
    sql,
    text,
)
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class ACL(Base):

    __tablename__ = 'auth_acl'

    id_ = Column(Integer, name='id', primary_key=True)
    value = Column(Text, nullable=False)
    token_uuid = Column(
        String(38), ForeignKey('auth_token.uuid', ondelete='CASCADE'), nullable=False
    )


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

    data_uuid = Column(
        String(36), ForeignKey('auth_external_auth_data.uuid', ondelete='CASCADE')
    )
    tenant_uuid = Column(
        String(38), ForeignKey('auth_tenant.uuid', ondelete='CASCADE'), primary_key=True
    )
    type_uuid = Column(
        String(36),
        ForeignKey('auth_external_auth_type.uuid', ondelete='CASCADE'),
        primary_key=True,
    )
    external_auth_data = relationship(
        'ExternalAuthData',
        cascade='all, delete-orphan',
        single_parent=True,
    )


class ExternalAuthType(Base):

    __tablename__ = 'auth_external_auth_type'

    uuid = Column(
        String(38), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    name = Column(Text, unique=True, nullable=False)
    enabled = Column(Boolean, server_default='false')


class ExternalAuthData(Base):

    __tablename__ = 'auth_external_auth_data'

    uuid = Column(
        String(38), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    data = Column(Text, nullable=False)


class Group(Base):

    __tablename__ = 'auth_group'

    uuid = Column(
        String(38), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    name = Column(Text, unique=True, nullable=False)
    tenant_uuid = Column(
        String(38), ForeignKey('auth_tenant.uuid', ondelete='CASCADE'), nullable=False
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
    phone = Column(Text)
    contact_uuid = Column(String(38), ForeignKey('auth_user.uuid', ondelete='SET NULL'))
    parent_uuid = Column(String(38), ForeignKey('auth_tenant.uuid'), nullable=False)

    # FIXME(fblackburn): delete CASCADE is not enough for all sub-relation
    external_auth_config = relationship('ExternalAuthConfig', cascade='all, delete-orphan')
    users = relationship(
        'User',
        foreign_keys='User.tenant_uuid',
        cascade='all, delete-orphan'
    )


class Token(Base):

    __tablename__ = 'auth_token'

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

    acls = relationship('ACL')
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
    __table_args__ = (UniqueConstraint('name', 'tenant_uuid'),)

    uuid = Column(
        String(38), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    name = Column(String(80), nullable=False)
    description = Column(Text)
    tenant_uuid = Column(
        String(38), ForeignKey('auth_tenant.uuid', ondelete='CASCADE'), nullable=False
    )
    tenant = relationship('Tenant', cascade='all, delete-orphan', single_parent=True)


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
    user_external_auth = relationship('UserExternalAuth', cascade='all, delete-orphan')


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
    external_auth_data_uuid = Column(
        String(38),
        ForeignKey('auth_external_auth_data.uuid', ondelete='CASCADE'),
        primary_key=True,
    )

    external_auth_data = relationship(
        'ExternalAuthData',
        cascade='all, delete-orphan',
        single_parent=True,
    )


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


# FIXME(fblackburn): remove unused ACLTemplate
class ACLTemplate(Base):

    __tablename__ = 'auth_acl_template'
    __table_args__ = (UniqueConstraint('template'),)

    id_ = Column(Integer, name='id', primary_key=True)
    template = Column(Text, nullable=False)


class ACLTemplatePolicy(Base):

    __tablename__ = 'auth_policy_template'

    policy_uuid = Column(
        String(38), ForeignKey('auth_policy.uuid', ondelete='CASCADE'), primary_key=True
    )
    template_id = Column(
        Integer,
        ForeignKey('auth_acl_template.id', ondelete='CASCADE'),
        primary_key=True,
    )
