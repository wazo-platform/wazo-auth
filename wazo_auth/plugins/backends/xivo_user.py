# -*- coding: utf-8 -*-
#
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
#
# SPDX-License-Identifier: GPL-3.0+

import logging

from wazo_auth import UserAuthenticationBackend
from xivo_dao.resources.user import dao as user_dao
from xivo_dao.helpers.db_utils import session_scope

logger = logging.getLogger(__name__)


class XiVOUser(UserAuthenticationBackend):

    def load(self, dependencies):
        super(XiVOUser, self).load(dependencies)
        config = dependencies['config']
        self._confd_config = config['confd']

    def get_acls(self, login, args):
        acl_templates = args.get('acl_templates', [])
        return self.render_acl(acl_templates, self.get_user_data, username=login)

    def get_ids(self, username, args):
        with session_scope():
            user = user_dao.get_by(username=username, enableclient=1)
            return user.uuid, user.uuid

    def verify_password(self, login, password, args):
        with session_scope():
            user = user_dao.find_by(username=login, password=password, enableclient=1)
            return user is not None
