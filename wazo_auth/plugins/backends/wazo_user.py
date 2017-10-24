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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import logging

from wazo_auth import ACLRenderingBackend, BaseAuthenticationBackend

logger = logging.getLogger(__name__)


class WazoUser(BaseAuthenticationBackend, ACLRenderingBackend):

    def get_acls(self, username, args):
        logger.debug('get_acls for %s', username)
        acl_templates = args.get('acl_templates', [])
        return self.render_acl(acl_templates, self.get_user_data, username=username)

    def get_ids(self, username, args):
        logger.debug('get_ids for %s', username)
        matching_users = self._user_service.list_users(username=username)
        return matching_users[0]['uuid'], None

    def verify_password(self, username, password, args):
        logger.debug('verify password for %s', username)
        return self._verify_password(username, password)

    def get_user_data(self, *args, **kwargs):
        logger.debug('getting user data %s %s', args, kwargs)
        return {}
