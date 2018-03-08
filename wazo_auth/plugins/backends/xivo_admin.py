# -*- coding: utf-8 -*-
# Copyright 2015-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import xivo_dao

from xivo_dao import admin_dao
from xivo_dao.helpers.exception import NotFoundError
from xivo_dao.helpers.db_utils import session_scope

from wazo_auth import BaseAuthenticationBackend, ACLRenderingBackend
from wazo_auth.exceptions import AuthenticationFailedException


class XiVOAdmin(BaseAuthenticationBackend, ACLRenderingBackend):

    def load(self, dependencies):
        super(XiVOAdmin, self).load(dependencies)
        self._tenant_service = dependencies['tenant_service']
        xivo_dao.init_db_from_config(dependencies['config'])

    def get_acls(self, login, args):
        acl_templates = args.get('acl_templates', [])
        return self.render_acl(acl_templates, lambda: args['metadata'])

    def get_metadata(self, login, args=None):
        metadata = super(XiVOAdmin, self).get_metadata(login, args)
        with session_scope():
            try:
                metadata['auth_id'] = admin_dao.get_admin_uuid(login)
            except NotFoundError:
                raise AuthenticationFailedException()

            entity = admin_dao.get_admin_entity(login)
            metadata['entity'] = entity
            metadata['tenants'] = self._build_tenants(entity)

        return metadata

    def verify_password(self, login, password, args):
        with session_scope():
            return admin_dao.check_username_password(login, password)

    def _build_tenants(self, entity):
        if entity:
            matching = self._tenant_service.list_(name=entity)
        else:
            matching = self._tenant_service.list_()

        return [{'uuid': tenant['uuid'], 'name': tenant['name']} for tenant in matching]
