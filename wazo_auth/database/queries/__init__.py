# -*- coding: utf-8 -*-
# Copyright 2016-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from .address import AddressDAO
from .email import EmailDAO
from .external_auth import ExternalAuthDAO
from .group import GroupDAO
from .policy import PolicyDAO
from .tenant import TenantDAO
from .token import TokenDAO
from .user import UserDAO


class DAO(object):

    _daos = {
        'address': AddressDAO,
        'email': EmailDAO,
        'external_auth': ExternalAuthDAO,
        'group': GroupDAO,
        'policy': PolicyDAO,
        'tenant': TenantDAO,
        'token': TokenDAO,
        'user': UserDAO,
    }

    def __init__(self, **kwargs):
        for name, dao in kwargs.iteritems():
            setattr(self, name, dao)

    @classmethod
    def from_config(cls, config):
        return cls(**{name: DAO(config['db_uri']) for name, DAO in cls._daos.iteritems()})
