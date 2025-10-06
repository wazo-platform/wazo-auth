# Copyright 2018-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
import threading
from functools import partial

import marshmallow
import websocket
from wazo_bus.resources.auth.events import (
    UserExternalAuthAddedEvent,
    UserExternalAuthAuthorizedEvent,
    UserExternalAuthDeletedEvent,
    UserExternalAuthUpdatedEvent,
)

from wazo_auth import exceptions
from wazo_auth.database.helpers import commit_or_rollback
from wazo_auth.exceptions import UnknownUserException
from wazo_auth.services.helpers import BaseService

logger = logging.getLogger(__name__)


class _OAuth2Synchronizer:
    def __init__(self, config, bus_publisher):
        self._url_tpl = config['oauth2_synchronization_ws_url_template']
        self._bus_publisher = bus_publisher

    def synchronize(self, event, state, success_cb):
        logger.debug('starting synchronization')
        websocket_client_thread = threading.Thread(
            target=self._synchronize, args=(event, state, success_cb)
        )
        websocket_client_thread.daemon = True
        websocket_client_thread.start()
        logger.debug('synchronization started')

    def _synchronize(self, event, state, success_cb):
        url = self._url_tpl.format(state=state)
        logger.debug('waiting on external authentication to complete %s...', url)
        ws = websocket.WebSocketApp(
            url,
            on_message=partial(self._on_message, event, success_cb),
            on_error=self._on_error,
            on_close=self._on_close,
        )
        ws.run_forever()

    def _on_message(self, event, success_cb, ws, msg):
        logger.debug('ws message received: %s', msg)
        try:
            msg = json.loads(msg)
            success_cb(msg)
            commit_or_rollback()
            headers = {'tenant_uuid': event.tenant_uuid}
            self._bus_publisher.publish(event, headers=headers)
        finally:
            ws.close()

    def _on_error(self, ws, error):
        logger.debug('ws error: %s', error)

    def _on_close(self, ws, status_code, message):
        logger.debug('ws closed')


class ExternalAuthService(BaseService):
    def __init__(self, dao, config, bus_publisher=None, enabled_external_auth=None):
        super().__init__(dao)
        self._bus_publisher = bus_publisher
        self._safe_models = {}
        self._enabled_external_auth = enabled_external_auth or []
        self._enabled_external_auth_populated = False
        self._url_tpl = config['oauth2_synchronization_redirect_url_template']
        self._oauth2_synchronizer = _OAuth2Synchronizer(config, bus_publisher)

    def _populate_enabled_external_auth(self):
        if self._enabled_external_auth_populated:
            return
        self._dao.external_auth.enable_all(self._enabled_external_auth)
        self._enabled_external_auth_populated = True

    def _get_user_tenant_uuid(self, user_uuid):
        users = self._dao.user.list_(uuid=user_uuid, limit=1)
        if not users:
            raise UnknownUserException(user_uuid)
        user = users[0]
        return user['tenant_uuid']

    def count(self, user_uuid, **kwargs):
        self._populate_enabled_external_auth()
        return self._dao.external_auth.count(user_uuid, **kwargs)

    def count_connected_users(
        self, auth_type, scoping_tenant_uuid=None, recurse=False, **kwargs
    ):
        self._populate_enabled_external_auth()

        if scoping_tenant_uuid:
            kwargs['tenant_uuids'] = self._get_scoped_tenant_uuids(
                scoping_tenant_uuid, recurse
            )

        return self._dao.external_auth.count_connected_users(auth_type, **kwargs)

    def create(self, user_uuid, auth_type, data):
        result = self._dao.external_auth.create(user_uuid, auth_type, data)
        tenant_uuid = self._get_user_tenant_uuid(user_uuid)
        event = UserExternalAuthAddedEvent(auth_type, tenant_uuid, user_uuid)
        self._bus_publisher.publish(event)
        return result

    def create_config(self, auth_type, data, tenant_uuid):
        return self._dao.external_auth.create_config(auth_type, data, tenant_uuid)

    def delete(self, user_uuid, auth_type):
        self._dao.external_auth.delete(user_uuid, auth_type)
        tenant_uuid = self._get_user_tenant_uuid(user_uuid)
        event = UserExternalAuthDeletedEvent(auth_type, tenant_uuid, user_uuid)
        self._bus_publisher.publish(event)

    def delete_config(self, auth_type, tenant_uuid):
        self._dao.external_auth.delete_config(auth_type, tenant_uuid)

    def get(self, user_uuid, auth_type):
        return self._dao.external_auth.get(user_uuid, auth_type)

    def get_config(self, auth_type, tenant_uuid):
        return self._dao.external_auth.get_config(auth_type, tenant_uuid)

    def list_connected_users(
        self, auth_type, scoping_tenant_uuid=None, recurse=True, **kwargs
    ):
        self._populate_enabled_external_auth()

        if scoping_tenant_uuid:
            kwargs['tenant_uuids'] = self._get_scoped_tenant_uuids(
                scoping_tenant_uuid, recurse
            )

        return self._dao.external_auth.list_connected_users(auth_type, **kwargs)

    def list_(self, user_uuid, **kwargs):
        self._populate_enabled_external_auth()
        raw_external_auth_info = self._dao.external_auth.list_(user_uuid, **kwargs)
        result = []
        for external_auth in raw_external_auth_info:
            auth_type = external_auth['type']
            enabled = external_auth['enabled']
            Model = self._safe_models.get(auth_type)
            filtered_data = {}
            if Model:
                data = external_auth.get('data')
                try:
                    filtered_data = Model().load(data)
                except marshmallow.ValidationError as e:
                    filtered_data = e.valid_data
                    logger.info(
                        'Failed to parse %s data for user %s: %s',
                        auth_type,
                        user_uuid,
                        e.messages,
                    )
            result.append(
                {'type': auth_type, 'data': filtered_data, 'enabled': enabled}
            )
        return result

    def build_oauth2_redirect_url(self, auth_type):
        return self._url_tpl.format(auth_type=auth_type)

    def register_oauth2_callback(
        self, auth_type, user_uuid, state, cb, *args, **kwargs
    ):
        tenant_uuid = self._get_user_tenant_uuid(user_uuid)
        event = UserExternalAuthAuthorizedEvent(auth_type, tenant_uuid, user_uuid)
        self._oauth2_synchronizer.synchronize(
            event, state, partial(cb, *args, **kwargs)
        )

    def register_safe_auth_model(self, auth_type, model_class):
        self._safe_models[auth_type] = model_class

    def update(self, user_uuid, auth_type, data):
        updated = self._dao.external_auth.update(user_uuid, auth_type, data)
        tenant_uuid = self._get_user_tenant_uuid(user_uuid)
        event = UserExternalAuthUpdatedEvent(auth_type, tenant_uuid, user_uuid)
        self._bus_publisher.publish(event)
        return updated

    def update_or_create(self, user_uuid, auth_type, data):
        try:
            return self.update(user_uuid, auth_type, data)
        except exceptions.UnknownExternalAuthException:
            return self.create(user_uuid, auth_type, data)

    def update_config(self, auth_type, data, tenant_uuid):
        return self._dao.external_auth.update_config(auth_type, data, tenant_uuid)
