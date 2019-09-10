# Copyright 2016-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from .address import AddressDAO
from .email import EmailDAO
from .external_auth import ExternalAuthDAO
from .group import GroupDAO
from .policy import PolicyDAO
from .session import SessionDAO
from .tenant import TenantDAO
from .token import TokenDAO
from .user import UserDAO
from .refresh_token import RefreshTokenDAO

from xivo import sqlalchemy_helper


class DAO:

    _daos = {
        'address': AddressDAO,
        'email': EmailDAO,
        'external_auth': ExternalAuthDAO,
        'group': GroupDAO,
        'policy': PolicyDAO,
        'refresh_token': RefreshTokenDAO,
        'session': SessionDAO,
        'tenant': TenantDAO,
        'token': TokenDAO,
        'user': UserDAO,
    }

    def __init__(self, **kwargs):
        sqlalchemy_helper.handle_db_restart()
        for name, dao in kwargs.items():
            setattr(self, name, dao)

    @classmethod
    def from_config(cls, config):
        return cls(**{name: DAO(config['db_uri']) for name, DAO in cls._daos.items()})
