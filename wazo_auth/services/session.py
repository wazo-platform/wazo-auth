# Copyright 2019-2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo_bus.resources.auth.events import SessionDeletedEvent

from wazo_auth.services.helpers import BaseService


class SessionService(BaseService):
    def __init__(self, dao, tenant_tree, bus_publisher):
        super().__init__(dao, tenant_tree)
        self._bus_publisher = bus_publisher

    def count(self, scoping_tenant_uuid, recurse=False, **kwargs):
        if scoping_tenant_uuid:
            kwargs['tenant_uuids'] = self._get_scoped_tenant_uuids(
                scoping_tenant_uuid, recurse
            )
        return self._dao.session.count(**kwargs)

    def list_(self, scoping_tenant_uuid=None, recurse=False, **kwargs):
        if scoping_tenant_uuid:
            kwargs['tenant_uuids'] = self._get_scoped_tenant_uuids(
                scoping_tenant_uuid, recurse
            )

        return self._dao.session.list_(**kwargs)

    def delete(self, scoping_tenant_uuid, session_uuid):
        tenant_uuids = self._tenant_tree.list_visible_tenants(scoping_tenant_uuid)
        session, token = self._dao.session.delete(session_uuid, tenant_uuids)
        if not token:
            return

        event = SessionDeletedEvent(
            session['uuid'], session['tenant_uuid'], token['auth_id']
        )
        self._bus_publisher.publish(event)
