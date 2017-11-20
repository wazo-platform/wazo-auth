# -*- coding: utf-8 -*-
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from xivo_dao import accesswebservice_dao
from xivo_dao.helpers.db_utils import session_scope

from wazo_auth import BaseAuthenticationBackend
from wazo_auth.exceptions import AuthenticationFailedException

logger = logging.getLogger(__name__)


class XiVOService(BaseAuthenticationBackend):

    def get_acls(self, login, args):
        with session_scope():
            return accesswebservice_dao.get_user_acl(login)

    def get_ids(self, login, args):
        with session_scope():
            try:
                auth_id = accesswebservice_dao.get_user_uuid(login)
            except LookupError:
                raise AuthenticationFailedException()

        user_uuid = None
        return auth_id, user_uuid

    def verify_password(self, login, password, args):
        with session_scope():
            return accesswebservice_dao.check_username_password(login, password)
