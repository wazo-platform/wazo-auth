# -*- coding: utf-8 -*-
# Copyright 2015-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging
import xivo_dao

from xivo_dao import accesswebservice_dao
from xivo_dao.helpers.db_utils import session_scope

from wazo_auth import BaseAuthenticationBackend
from wazo_auth.exceptions import AuthenticationFailedException

logger = logging.getLogger(__name__)


class XiVOService(BaseAuthenticationBackend):

    def load(self, dependencies):
        super(XiVOService, self).load(dependencies)
        self._tenant_service = dependencies['tenant_service']
        xivo_dao.init_db_from_config(dependencies['config'])

    def get_acls(self, login, args):
        with session_scope():
            return accesswebservice_dao.get_user_acl(login)

    def get_metadata(self, login, args):
        metadata = super(XiVOService, self).get_metadata(login, args)
        with session_scope():
            try:
                metadata['auth_id'] = accesswebservice_dao.get_user_uuid(login)
            except LookupError:
                raise AuthenticationFailedException()
        metadata['tenants'] = self._get_all_tenants()
        return metadata

    def verify_password(self, login, password, args):
        with session_scope():
            return accesswebservice_dao.check_username_password(login, password)

    def _get_all_tenants(self):
        return [
            {'uuid': tenant['uuid'], 'name': tenant['name']}
            for tenant in self._tenant_service.list_()
        ]
