# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from wazo_auth.exceptions import InvalidUsernamePassword, NoSuchBackendException

logger = logging.getLogger(__name__)


class AuthenticationService:
    def __init__(self, dao, backends):
        self._dao = dao
        self._backends = backends

    def verify_auth(self, args):
        refresh_token = args.get('refresh_token')
        if refresh_token:
            refresh_token_data = self._dao.refresh_token.get(
                refresh_token, args['client_id']
            )
            backend = self._get_backend(refresh_token_data['backend_name'])
            return backend, refresh_token_data['login']
        else:
            backend = self._get_backend(args['backend'])
            login = args.get('login', '')
            if not backend.verify_password(login, args.pop('password', ''), args):
                raise InvalidUsernamePassword(login)
            return backend, login

    def _get_backend(self, backend_name):
        try:
            return self._backends[backend_name].obj
        except KeyError:
            logger.debug('backend not found: "%s"', backend_name)
            raise NoSuchBackendException(backend_name)
