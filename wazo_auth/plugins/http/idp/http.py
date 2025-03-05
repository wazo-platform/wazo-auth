# Copyright 2024-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import marshmallow
from flask import request

from wazo_auth import exceptions, http
from wazo_auth.flask_helpers import Tenant
from wazo_auth.services.idp import IDPService
from wazo_auth.services.user import UserService

from .schemas import IDPUsersSchema


class IDPList(http.AuthResource):
    def __init__(self, idp_types: set[str]) -> None:
        super().__init__()
        self._idp_types = idp_types

    @http.required_acl('auth.idp.read')
    def get(self):
        items = list(self._idp_types)
        count = len(items)
        return {'total': count, 'filtered': count, 'items': items}


class _BaseIDPUser(http.AuthResource):
    def __init__(self, user_service: UserService, idp_service: IDPService):
        self._user_service = user_service
        self._idp_service = idp_service

    def _validate_idp_type(self, type_):
        if not self._idp_service.is_valid_idp_type(type_):
            raise exceptions.UnknownIDPType(type_)


class IDPUser(_BaseIDPUser):
    @http.required_acl('auth.idp.{idp_type}.users.{user_uuid}.create')
    def put(self, idp_type, user_uuid):
        self._validate_idp_type(idp_type)
        scoping_tenant = Tenant.autodetect()

        self._user_service.assert_user_in_subtenant(scoping_tenant.uuid, user_uuid)

        self._idp_service.add_user(idp_type, user_uuid)
        return '', 204

    @http.required_acl('auth.idp.{idp_type}.users.{user_uuid}.delete')
    def delete(self, idp_type, user_uuid):
        self._validate_idp_type(idp_type)
        scoping_tenant = Tenant.autodetect()

        self._user_service.assert_user_in_subtenant(scoping_tenant.uuid, user_uuid)

        self._idp_service.remove_user(idp_type, user_uuid)
        return '', 204


class IDPUsers(_BaseIDPUser):
    @http.required_acl('auth.idp.{idp_type}.users.update')
    def put(self, idp_type):
        self._validate_idp_type(idp_type)
        scoping_tenant = Tenant.autodetect()

        try:
            form = IDPUsersSchema().load(request.get_json())
        except marshmallow.ValidationError as e:
            raise exceptions.InvalidListParamException(e.messages)

        for user in form['users']:
            self._user_service.assert_user_in_subtenant(
                scoping_tenant.uuid, user['uuid']
            )
            self._idp_service.add_user(idp_type, user['uuid'])
        return '', 204
