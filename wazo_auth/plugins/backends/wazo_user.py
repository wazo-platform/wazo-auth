# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from wazo_auth import ACLRenderingBackend, BaseAuthenticationBackend

logger = logging.getLogger(__name__)


class WazoUser(BaseAuthenticationBackend, ACLRenderingBackend):

    def load(self, dependencies):
        super(WazoUser, self).load(dependencies)
        self._user_service = dependencies['user_service']
        self._group_service = dependencies['group_service']

    def get_acls(self, username, args):
        backend_acl_templates = args.get('acl_templates', [])
        group_acl_templates = self._group_service.get_acl_templates(username)
        user_acl_templates = self._user_service.get_acl_templates(username)

        acl_templates = backend_acl_templates + group_acl_templates + user_acl_templates

        return self.render_acl(acl_templates, self.get_user_data, username=username)

    def get_ids(self, username, args):
        uuid = self._get_user_uuid(username)
        return uuid, uuid

    def verify_password(self, username, password, args):
        return self._user_service.verify_password(username, password)

    def get_user_data(self, *args, **kwargs):
        user_uuid = self._get_user_uuid(kwargs['username'])
        tenants = self._user_service.list_tenants(user_uuid)
        groups = self._user_service.list_groups(user_uuid)
        for group in groups:
            group['users'] = self._group_service.list_users(group['uuid'])

        return {
            'username': kwargs['username'],
            'tenants': tenants,
            'groups': groups,
        }

    def _get_user_uuid(self, username):
        matching_users = self._user_service.list_users(username=username)
        return matching_users[0]['uuid']
