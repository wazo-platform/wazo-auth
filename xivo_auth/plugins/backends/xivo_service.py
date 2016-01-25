# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Avencall
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import logging

from xivo_auth import BaseAuthenticationBackend

from xivo_dao import accesswebservice_dao
from xivo_dao.helpers.db_utils import session_scope

logger = logging.getLogger(__name__)


class XiVOService(BaseAuthenticationBackend):

    def get_consul_acls(self, login, args):
        acl = self.get_acls(login, args)
        consul_acl = []
        for access in acl:
            if access.startswith('dird'):
                consul_acl = [{'rule': 'xivo/private',
                               'policy': 'read'}]
        return consul_acl

    def get_acls(self, login, args):
        with session_scope():
            return accesswebservice_dao.get_user_acl(login)

    def get_ids(self, login, args):
        with session_scope():
            auth_id = str(accesswebservice_dao.get_user_id(login))
        user_uuid = None
        return auth_id, user_uuid

    def verify_password(self, login, password):
        with session_scope():
            return accesswebservice_dao.check_username_password(login, password)
