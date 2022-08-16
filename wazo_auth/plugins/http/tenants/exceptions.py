# Copyright 2021-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo.rest_api_helpers import APIException


class DeleteOwnTenantForbidden(APIException):
    def __init__(self, tenant_uuid):
        details = {'tenant_uuid': str(tenant_uuid)}
        msg = f'Deleting its own tenant is forbidden: "{tenant_uuid}"'
        error_id = 'deleting-own-tenant-forbidden'
        super().__init__(403, msg, error_id, details, resource='tenants')
