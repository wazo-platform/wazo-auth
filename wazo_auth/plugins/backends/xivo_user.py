# -*- coding: utf-8 -*-
#
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
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
