# Copyright 2019-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth.services.helpers import BaseService
from xivo_bus.resources.auth.events import SessionDeletedEvent, UserSessionsUpdatedEvent


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

        self.notify_session_deleted(
            session['uuid'],
            token['auth_id'],
            session['tenant_uuid'],
        )

    def notify_session_deleted(self, session_uuid, user_uuid, tenant_uuid):
        headers = {
            f'user_uuid:{user_uuid}': True,
            'tenant_uuid': tenant_uuid,
        }

        event = SessionDeletedEvent(
            uuid=session_uuid,
            user_uuid=user_uuid,
            tenant_uuid=tenant_uuid,
        )
        self._bus_publisher.publish(event, headers=headers)

        sessions = self._dao.session.list_(
            user_uuid=user_uuid,
            tenant_uuids=[tenant_uuid],
        )
        event = UserSessionsUpdatedEvent(
            user_uuid=user_uuid,
            tenant_uuid=tenant_uuid,
            sessions=sessions,
        )
        self._bus_publisher.publish(event, headers=headers)
