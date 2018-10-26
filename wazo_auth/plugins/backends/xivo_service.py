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

    def __init__(self, *args, **kwargs):
        super(XiVOService, self).__init__(*args, **kwargs)

    def load(self, dependencies):
        super(XiVOService, self).load(dependencies)
        self._tenant_service = dependencies['tenant_service']
        xivo_dao.init_db(dependencies['config']['confd_db_uri'])

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
        metadata['tenant_uuid'] = self._tenant_service.find_top_tenant()
        return metadata

    def verify_password(self, login, password, args):
        with session_scope():
            return accesswebservice_dao.check_username_password(login, password)
