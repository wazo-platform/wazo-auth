# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth.services.helpers import BaseService


class SessionService(BaseService):

    def count(self, scoping_tenant_uuid, recurse=False, **kwargs):
        if scoping_tenant_uuid:
            kwargs['tenant_uuids'] = self._get_scoped_tenant_uuids(scoping_tenant_uuid, recurse)
        return self._dao.session.count(**kwargs)

    def list_(self, scoping_tenant_uuid=None, recurse=False, **kwargs):
        if scoping_tenant_uuid:
            kwargs['tenant_uuids'] = self._get_scoped_tenant_uuids(scoping_tenant_uuid, recurse)

        return self._dao.session.list_(**kwargs)
