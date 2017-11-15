# -*- coding: utf-8 -*-
#
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
#
# SPDX-License-Identifier: GPL-3.0+


from xivo_dao import admin_dao
from xivo_dao.helpers.exception import NotFoundError
from xivo_dao.helpers.db_utils import session_scope

from wazo_auth import BaseAuthenticationBackend, ACLRenderingBackend
from wazo_auth.exceptions import AuthenticationFailedException


class XiVOAdmin(BaseAuthenticationBackend, ACLRenderingBackend):

    def get_acls(self, login, args):
        acl_templates = args.get('acl_templates', [])
        return self.render_acl(acl_templates, self.get_admin_data, username=login)

    def get_admin_data(self, username):
        with session_scope():
            entity = admin_dao.get_admin_entity(username)

        return {'entity': entity}

    def get_ids(self, username, args):
        with session_scope():
            try:
                auth_id = admin_dao.get_admin_uuid(username)
            except NotFoundError:
                raise AuthenticationFailedException()

        user_uuid = None
        return auth_id, user_uuid

    def verify_password(self, login, password, args):
        with session_scope():
            return admin_dao.check_username_password(login, password)
