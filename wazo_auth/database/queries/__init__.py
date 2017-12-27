# -*- coding: utf-8 -*-
# Copyright 2016-2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from .email import EmailDAO
from .external_auth import ExternalAuthDAO
from .group import GroupDAO
from .policy import PolicyDAO
from .tenant import TenantDAO
from .token import TokenDAO
from .user import UserDAO


class DAO(object):

    def __init__(self, policy_dao, token_dao, user_dao, tenant_dao, group_dao, external_auth_dao, email_dao):
        self.email = email_dao
        self.external_auth = external_auth_dao
        self.policy = policy_dao
        self.token = token_dao
        self.user = user_dao
        self.tenant = tenant_dao
        self.group = group_dao

    @classmethod
    def from_config(cls, config):
        email = EmailDAO(config['db_uri'])
        external_auth = ExternalAuthDAO(config['db_uri'])
        group = GroupDAO(config['db_uri'])
        policy = PolicyDAO(config['db_uri'])
        token = TokenDAO(config['db_uri'])
        user = UserDAO(config['db_uri'])
        tenant = TenantDAO(config['db_uri'])
        return cls(policy, token, user, tenant, group, external_auth, email)
