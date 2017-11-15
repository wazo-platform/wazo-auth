# -*- coding: utf-8 -*-
#
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>

from sqlalchemy import (
    Boolean, Column, ForeignKey, Integer, LargeBinary,
    schema, String, Text, text, UniqueConstraint,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class ACL(Base):

    __tablename__ = 'auth_acl'

    id_ = Column(Integer, name='id', primary_key=True)
    value = Column(Text, nullable=False)
    token_uuid = Column(String(38), ForeignKey('auth_token.uuid', ondelete='CASCADE'), nullable=False)


class Email(Base):

    __tablename__ = 'auth_email'

    uuid = Column(String(38), server_default=text('uuid_generate_v4()'), primary_key=True)
    address = Column(Text, unique=True, nullable=False)
    confirmed = Column(Boolean, nullable=False, default=False)


class Group(Base):

    __tablename__ = 'auth_group'

    uuid = Column(String(38), server_default=text('uuid_generate_v4()'), primary_key=True)
    name = Column(Text, unique=True, nullable=False)


class Tenant(Base):

    __tablename__ = 'auth_tenant'

    uuid = Column(String(38), server_default=text('uuid_generate_v4()'), primary_key=True)
    name = Column(Text, unique=True, nullable=False)


class TenantUser(Base):

    __tablename__ = 'auth_tenant_user'

    tenant_uuid = Column(String(38), ForeignKey('auth_tenant.uuid', ondelete='CASCADE'), primary_key=True)
    user_uuid = Column(String(38), ForeignKey('auth_user.uuid', ondelete='CASCADE'), primary_key=True)


class Token(Base):

    __tablename__ = 'auth_token'

    uuid = Column(String(38), server_default=text('uuid_generate_v4()'), primary_key=True)
    auth_id = Column(Text, nullable=False)
    user_uuid = Column(String(38))
    xivo_uuid = Column(String(38))
    issued_t = Column(Integer)
    expire_t = Column(Integer)
    acls = relationship('ACL')


class Policy(Base):

    __tablename__ = 'auth_policy'
    __table_args__ = (
        UniqueConstraint('name'),
    )

    uuid = Column(String(38), server_default=text('uuid_generate_v4()'), primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(Text)


class User(Base):

    __tablename__ = 'auth_user'

    uuid = Column(String(38), server_default=text('uuid_generate_v4()'), primary_key=True)
    username = Column(String(128), unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    password_salt = Column(LargeBinary, nullable=False)


class UserEmail(Base):

    __tablename__ = 'auth_user_email'
    __table_args__ = (
        schema.UniqueConstraint('user_uuid', 'main'),
    )

    user_uuid = Column(String(38), ForeignKey('auth_user.uuid', ondelete='CASCADE'), primary_key=True)
    email_uuid = Column(String(38), ForeignKey('auth_email.uuid', ondelete='CASCADE'), primary_key=True)
    main = Column(Boolean, nullable=False, default=False)


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
