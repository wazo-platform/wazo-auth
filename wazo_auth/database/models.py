# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    schema,
    text,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class ACL(Base):

    __tablename__ = 'auth_acl'

    id_ = Column(Integer, name='id', primary_key=True)
    value = Column(Text, nullable=False)
    token_uuid = Column(String(38), ForeignKey('auth_token.uuid', ondelete='CASCADE'), nullable=False)


class Address(Base):

    __tablename__ = 'auth_address'

    id_ = Column(Integer, name='id', primary_key=True)
    line_1 = Column(Text)
    line_2 = Column(Text)
    city = Column(Text)
    state = Column(Text)
    zip_code = Column(Text)
    country = Column(Text)


class Email(Base):

    __tablename__ = 'auth_email'

    uuid = Column(String(38), server_default=text('uuid_generate_v4()'), primary_key=True)
    address = Column(Text, unique=True, nullable=False)
    confirmed = Column(Boolean, nullable=False, default=False)


class ExternalAuthType(Base):

    __tablename__ = 'auth_external_auth_type'

    uuid = Column(String(38), server_default=text('uuid_generate_v4()'), primary_key=True)
    name = Column(Text, unique=True, nullable=False)
    enabled = Column(Boolean, server_default='false')


class ExternalAuthData(Base):

    __tablename__ = 'auth_external_auth_data'

    uuid = Column(String(38), server_default=text('uuid_generate_v4()'), primary_key=True)
    data = Column(Text, nullable=False)


class Group(Base):

    __tablename__ = 'auth_group'

    uuid = Column(String(38), server_default=text('uuid_generate_v4()'), primary_key=True)
    name = Column(Text, unique=True, nullable=False)
    tenant_uuid = Column(String(38), ForeignKey('auth_tenant.uuid', ondelete='CASCADE'), nullable=False)


class GroupPolicy(Base):

    __tablename__ = 'auth_group_policy'

    policy_uuid = Column(String(38), ForeignKey('auth_policy.uuid', ondelete='CASCADE'), primary_key=True)
    group_uuid = Column(String(38), ForeignKey('auth_group.uuid', ondelete='CASCADE'), primary_key=True)


class Tenant(Base):

    __tablename__ = 'auth_tenant'

    uuid = Column(String(38), server_default=text('uuid_generate_v4()'), primary_key=True)
    name = Column(Text)
    phone = Column(Text)
    address_id = Column(Integer, ForeignKey('auth_address.id', ondelete='SET NULL'))
    contact_uuid = Column(String(38), ForeignKey('auth_user.uuid', ondelete='SET NULL'))
    parent_uuid = Column(String(38), ForeignKey('auth_tenant.uuid'), nullable=False)


class Token(Base):

    __tablename__ = 'auth_token'

    uuid = Column(String(38), server_default=text('uuid_generate_v4()'), primary_key=True)
    session_uuid = Column(
        String(36),
        ForeignKey('auth_session.uuid', ondelete='CASCADE'),
        nullable=False,
    )
    auth_id = Column(Text, nullable=False)
    user_uuid = Column(String(38))
    xivo_uuid = Column(String(38))
    issued_t = Column(Integer)
    expire_t = Column(Integer)
    acls = relationship('ACL')
    metadata_ = Column(Text, name='metadata')


class Session(Base):

    __tablename__ = 'auth_session'

    uuid = Column(String(36), server_default=text('uuid_generate_v4()'), primary_key=True)
    mobile = Column(Boolean, nullable=False, default=False)


class Policy(Base):

    __tablename__ = 'auth_policy'
    __table_args__ = (
        UniqueConstraint('name', 'tenant_uuid'),
    )

    uuid = Column(String(38), server_default=text('uuid_generate_v4()'), primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(Text)
    tenant_uuid = Column(String(38), ForeignKey('auth_tenant.uuid', ondelete='CASCADE'), nullable=False)
    tenant = relationship('Tenant', cascade='all, delete-orphan', single_parent=True)


class User(Base):

    __tablename__ = 'auth_user'

    uuid = Column(String(38), server_default=text('uuid_generate_v4()'), primary_key=True)
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
    tenant_uuid = Column(String(38), ForeignKey('auth_tenant.uuid', ondelete='CASCADE'), nullable=False)
    emails = relationship('UserEmail', cascade='all, delete-orphan')


class UserEmail(Base):

    __tablename__ = 'auth_user_email'
    __table_args__ = (
        schema.UniqueConstraint('user_uuid', 'main'),
    )

    user_uuid = Column(String(38), ForeignKey('auth_user.uuid', ondelete='CASCADE'), primary_key=True)
    email_uuid = Column(String(38), ForeignKey('auth_email.uuid', ondelete='CASCADE'), primary_key=True)
    main = Column(Boolean, nullable=False, default=False)
    email = relationship('Email', cascade='all, delete-orphan', single_parent=True)


class UserExternalAuth(Base):

    __tablename__ = 'auth_user_external_auth'
    __table_args__ = (
        schema.UniqueConstraint('user_uuid', 'external_auth_type_uuid'),
    )

    user_uuid = Column(String(38), ForeignKey('auth_user.uuid', ondelete='CASCADE'), primary_key=True)
    external_auth_type_uuid = Column(String(38), ForeignKey('auth_external_auth_type.uuid', ondelete='CASCADE'), primary_key=True)
    external_auth_data_uuid = Column(String(38), ForeignKey('auth_external_auth_data.uuid', ondelete='CASCADE'), primary_key=True)


class UserGroup(Base):

    __tablename__ = 'auth_user_group'

    user_uuid = Column(String(38), ForeignKey('auth_user.uuid', ondelete='CASCADE'), primary_key=True)
    group_uuid = Column(String(38), ForeignKey('auth_group.uuid', ondelete='CASCADE'), primary_key=True)


class UserPolicy(Base):

    __tablename__ = 'auth_user_policy'

    user_uuid = Column(String(38), ForeignKey('auth_user.uuid', ondelete='CASCADE'), primary_key=True)
    policy_uuid = Column(String(38), ForeignKey('auth_policy.uuid', ondelete='CASCADE'), primary_key=True)


class ACLTemplate(Base):

    __tablename__ = 'auth_acl_template'
    __table_args__ = (
        UniqueConstraint('template'),
    )

    id_ = Column(Integer, name='id', primary_key=True)
    template = Column(Text, nullable=False)


class ACLTemplatePolicy(Base):

    __tablename__ = 'auth_policy_template'

    policy_uuid = Column(String(38), ForeignKey('auth_policy.uuid', ondelete='CASCADE'), primary_key=True)
    template_id = Column(Integer, ForeignKey('auth_acl_template.id', ondelete='CASCADE'), primary_key=True)
