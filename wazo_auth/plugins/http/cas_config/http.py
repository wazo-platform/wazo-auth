# Copyright 2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import marshmallow

from flask import request
from wazo_auth import exceptions
from wazo_auth.flask_helpers import Tenant
from wazo_auth.http import AuthResource

from xivo.auth_verifier import required_acl

from .schemas import cas_config_schema, cas_config_edit_schema


class CASConfig(AuthResource):
    def __init__(self, cas_service):
        self._cas_service = cas_service

    @required_acl('auth.backends.cas.read')
    def get(self):
        scoping_tenant = Tenant.autodetect()
        return cas_config_schema.dump(self._cas_service.get(scoping_tenant.uuid)), 200

    @required_acl('auth.backends.cas.update')
    def put(self):
        scoping_tenant = Tenant.autodetect()
        try:
            body = cas_config_edit_schema.load(request.get_json(force=True))
            body['tenant_uuid'] = scoping_tenant.uuid
            cas_config = self._cas_service.create_or_update(**body)
        except marshmallow.ValidationError as e:
            for field in e.messages:
                raise exceptions.InvalidInputException(field)
        return cas_config_schema.dump(cas_config), 200

    @required_acl('auth.backends.cas.delete')
    def delete(self):
        scoping_tenant = Tenant.autodetect()
        self._cas_service.delete(scoping_tenant.uuid)
        return '', 204
