# Copyright 2017-2025 The Wazo Authors  (see the AUTHORS file)
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
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
    schema,
    sql,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import backref, declarative_base, relationship
from sqlalchemy.sql.sqltypes import JSON

from wazo_auth.database.datatypes import XMLPostgresqlType

Base = declarative_base()

RFC_DN_MAX_LENGTH = 253


class Address(Base):
    __tablename__ = 'auth_address'
    __table_args__ = (Index('auth_address__idx__tenant_uuid', 'tenant_uuid'),)

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
    __table_args__ = (
        Index('auth_email_address_key', func.lower('address'), unique=True),
        Index('auth_email__idx__user_uuid', 'user_uuid'),
    )

    uuid = Column(
        String(38), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    address = Column(Text, nullable=False)
    confirmed = Column(Boolean, nullable=False, default=False)
    main = Column(Boolean, nullable=False, default=False)
    user_uuid = Column(
        String(38),
        ForeignKey('auth_user.uuid', ondelete='CASCADE'),
        nullable=False,
    )


class ExternalAuthConfig(Base):
    __tablename__ = 'auth_external_auth_config'
    __table_args__ = (Index('auth_external_auth_config__idx__type_uuid', 'type_uuid'),)

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
    __table_args__ = (Index('auth_group__idx__tenant_uuid', 'tenant_uuid'),)

    uuid = Column(
        String(38), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    name = Column(Text, unique=True, nullable=False)
    slug = Column(Text, unique=True, nullable=False)
    tenant_uuid = Column(
        String(38), ForeignKey('auth_tenant.uuid', ondelete='CASCADE'), nullable=False
    )
    system_managed = Column(
        Boolean, nullable=False, default=False, server_default='false'
    )

    user_groups = relationship('UserGroup', viewonly=True)


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
    __table_args__ = (
        Index('auth_tenant__idx__contact_uuid', 'contact_uuid'),
        Index('auth_tenant__idx__parent_uuid', 'parent_uuid'),
    )

    uuid = Column(
        String(38), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    name = Column(Text)
    slug = Column(String(10), nullable=False, unique=True)
    phone = Column(Text)
    contact_uuid = Column(String(38), ForeignKey('auth_user.uuid', ondelete='SET NULL'))
    parent_uuid = Column(String(38), ForeignKey('auth_tenant.uuid'), nullable=False)
    default_authentication_method = Column(
        Text,
        nullable=False,
    )
    domains = relationship(
        'Domain',
        cascade="all, delete-orphan",
        passive_deletes=True,
        backref='tenant',
    )
    address = relationship(
        'Address',
        uselist=False,
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    policies = relationship(
        'Policy',
        cascade="all, delete-orphan",
        passive_deletes=True,
        backref='tenant',
    )

    @hybrid_property
    def domain_names(self):
        if self.domains:
            return [domain.name for domain in self.domains]
        else:
            return []

    @domain_names.setter
    def domain_names(self, value):
        current_names = {domain.name for domain in self.domains}
        new_names = set(value)
        missing_names = new_names - current_names
        domains = set()

        for domain in self.domains:
            if domain.name in new_names:
                domains.add(domain)

        for name in missing_names:
            domains.add(Domain(name=name, tenant=self))

        self.domains = list(domains)


class Domain(Base):
    __tablename__ = 'auth_tenant_domain'
    __table_args__ = (Index('auth_tenant_domain__idx__tenant_uuid', 'tenant_uuid'),)

    uuid = Column(
        String(36), server_default=text('uuid_generate_v4()'), primary_key=True
    )

    name = Column(String(RFC_DN_MAX_LENGTH), nullable=False, unique=True)
    tenant_uuid = Column(
        String(38), ForeignKey('auth_tenant.uuid', ondelete='CASCADE'), nullable=False
    )


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
    refresh_token_uuid = Column(
        String(36),
        ForeignKey('auth_refresh_token.uuid', ondelete='CASCADE'),
        nullable=True,
    )
    session = relationship(
        'Session',
        cascade='all, delete-orphan',
        passive_deletes=True,
        single_parent=True,
        backref=backref('tokens', cascade='all, delete'),
    )


class RefreshToken(Base):
    __tablename__ = 'auth_refresh_token'
    __table_args__ = (
        UniqueConstraint('client_id', 'user_uuid'),
        Index('auth_refresh_token__idx__user_uuid', 'user_uuid'),
    )

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
    metadata_ = Column(JSON(), nullable=False, server_default='{}', name='metadata')
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
    __table_args__ = (Index('auth_session__idx__tenant_uuid', 'tenant_uuid'),)

    uuid = Column(
        String(36), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    tenant_uuid = Column(
        String(38), ForeignKey('auth_tenant.uuid', ondelete='CASCADE'), nullable=False
    )
    mobile = Column(Boolean, nullable=False, default=False)


class Policy(Base):
    __tablename__ = 'auth_policy'
    __table_args__ = (
        UniqueConstraint('name', 'tenant_uuid'),
        Index('auth_policy__idx__slug', func.lower('slug'), 'tenant_uuid', unique=True),
        Index('auth_policy__idx__tenant_uuid', 'tenant_uuid'),
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
    shared = Column(Boolean, default=False, server_default='false', nullable=False)

    accesses = relationship('Access', secondary='auth_policy_access', viewonly=True)
    groups = relationship('Group', secondary='auth_group_policy', viewonly=True)
    group_policies = relationship('GroupPolicy', viewonly=True)
    user_policies = relationship('UserPolicy', viewonly=True)

    @property
    def acl(self):
        return [access.access for access in self.accesses]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tenant_uuid_exposed = None
        self.read_only = None
        self.shared_exposed = None


class User(Base):
    __tablename__ = 'auth_user'
    __table_args__ = (
        Index('auth_user_username_key', func.lower('username'), unique=True),
        Index('auth_user__idx__tenant_uuid', 'tenant_uuid'),
    )

    uuid = Column(
        String(38), server_default=text('uuid_generate_v4()'), primary_key=True
    )
    username = Column(String(256))
    firstname = Column(Text)
    lastname = Column(Text)
    password_hash = Column(Text)
    password_salt = Column(LargeBinary)
    purpose = Column(
        Text,
        CheckConstraint("purpose in ('user', 'internal', 'external_api')"),
        nullable=False,
    )
    authentication_method = Column(
        Text,
        nullable=False,
    )
    enabled = Column(Boolean)
    tenant_uuid = Column(
        String(38), ForeignKey('auth_tenant.uuid', ondelete='CASCADE'), nullable=False
    )

    emails = relationship('Email', viewonly=True)
    user_groups = relationship('UserGroup', viewonly=True)


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


class LDAPConfig(Base):
    __tablename__ = 'auth_ldap_config'

    tenant_uuid = Column(
        String(38),
        ForeignKey('auth_tenant.uuid', ondelete='CASCADE'),
        nullable=False,
        primary_key=True,
    )
    host = Column(String(512), nullable=False)
    port = Column(Integer, nullable=False)
    protocol_version = Column(SmallInteger)
    protocol_security = Column(
        Text,
        CheckConstraint("protocol_security in ('ldaps', 'tls')"),
    )
    bind_dn = Column(String(256))
    bind_password = Column(Text)
    user_base_dn = Column(String(256), nullable=False)
    user_login_attribute = Column(String(64), nullable=False)
    user_email_attribute = Column(String(64), nullable=False)
    search_filters = Column(Text, nullable=True)


class SAMLConfig(Base):
    __tablename__ = 'auth_saml_config'

    tenant_uuid = Column(
        String(38),
        ForeignKey('auth_tenant.uuid', ondelete='CASCADE'),
        nullable=False,
        primary_key=True,
    )
    domain_uuid = Column(
        String(length=38),
        ForeignKey('auth_tenant_domain.uuid', ondelete='CASCADE'),
        nullable=False,
    )
    entity_id = Column(String(512), nullable=False)
    idp_metadata = Column(XMLPostgresqlType(), nullable=False)
    acs_url = Column(String(512), nullable=False)


class SAMLSession(Base):
    __tablename__ = 'auth_saml_session'

    request_id = Column(
        String(40),
        nullable=False,
        primary_key=True,
    )
    session_id = Column(
        String(length=22),
        nullable=False,
        primary_key=True,
    )
    redirect_url = Column(String(512), nullable=False)
    domain = Column(String(512), nullable=False)
    relay_state = Column(String(44), nullable=False)
    login = Column(String(512), nullable=True)
    start_time = Column(DateTime(timezone=True), nullable=True)
    saml_name_id = Column(Text, nullable=True)
    refresh_token_uuid = Column(
        String(36),
        ForeignKey('auth_refresh_token.uuid', ondelete='CASCADE'),
        nullable=True,
    )


class SAMLPysaml2Cache(Base):
    __tablename__ = 'auth_saml_pysaml2_cache'

    name_id = Column(
        String(512),
        nullable=False,
        primary_key=True,
    )
    entity_id = Column(
        String(1024),
        nullable=False,
        primary_key=True,
    )
    info = Column(Text(), nullable=False)
    not_on_or_after = Column(
        Integer(),
        nullable=False,
    )
