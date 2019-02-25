# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from flask import request
from wazo_auth import exceptions, http, schemas
from wazo_auth.flask_helpers import Tenant

logger = logging.getLogger(__name__)


class UserSessions(http.AuthResource):

    def __init__(self, user_service):
        self.user_service = user_service

    @http.required_acl('auth.users.{user_uuid}.sessions.read')
    def get(self, user_uuid):
        scoping_tenant = Tenant.autodetect()

        self.user_service.assert_user_in_subtenant(scoping_tenant.uuid, user_uuid)

        ListSchema = schemas.new_list_schema()
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        return {
            'items': self.user_service.list_sessions(user_uuid, **list_params),
            'total': self.user_service.count_sessions(user_uuid, filtered=False, **list_params),
            'filtered': self.user_service.count_sessions(user_uuid, filtered=True, **list_params),
        }, 200
