# Copyright 2016-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from .address import AddressDAO
from .email import EmailDAO
from .external_auth import ExternalAuthDAO
from .group import GroupDAO
from .ldap_config import LDAPConfigDAO
from .policy import PolicyDAO
from .session import SessionDAO
from .tenant import TenantDAO
from .token import TokenDAO
from .user import UserDAO
from .refresh_token import RefreshTokenDAO


class DAO:
    def __init__(
        self,
        address,
        email,
        external_auth,
        group,
        ldap_config,
        policy,
        refresh_token,
        session,
        tenant,
        token,
        user,
    ):
        self.address = address
        self.email = email
        self.external_auth = external_auth
        self.group = group
        self.ldap_config = ldap_config
        self.policy = policy
        self.refresh_token = refresh_token
        self.session = session
        self.tenant = tenant
        self.token = token
        self.user = user

    @classmethod
    def from_defaults(cls):
        return cls(
            address=AddressDAO(),
            email=EmailDAO(),
            external_auth=ExternalAuthDAO(),
            group=GroupDAO(),
            ldap_config=LDAPConfigDAO(),
            policy=PolicyDAO(),
            refresh_token=RefreshTokenDAO(),
            session=SessionDAO(),
            tenant=TenantDAO(),
            token=TokenDAO(),
            user=UserDAO(),
        )
