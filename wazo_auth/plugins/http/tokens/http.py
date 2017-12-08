# -*- coding: utf-8 -*-
# Copyright 2015-2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from flask import request
from wazo_auth import http
from . import schemas


class BaseResource(http.ErrorCatchingResource):

    def __init__(self, token_manager, backends):
        self._backends = backends
        self._token_manager = token_manager


class Tokens(BaseResource):

    def post(self):
        if request.authorization:
            login = request.authorization.username
            password = request.authorization.password
        else:
            login = ''
            password = ''

        args, error = schemas.TokenRequestSchema().load(request.get_json(force=True))
        if error:
            return http._error(400, unicode(error))

        backend_name = args['backend']
        try:
            backend = self._backends[backend_name].obj
        except KeyError:
            return http._error(401, 'Authentication Failed')

        if not backend.verify_password(login, password, args):
            return http._error(401, 'Authentication Failed')

        token = self._token_manager.new_token(backend, login, args)

        return {'data': token.to_dict()}, 200


class Token(BaseResource):

    def delete(self, token):
        self._token_manager.remove_token(token)

        return {'data': {'message': 'success'}}

    def get(self, token):
        scope = request.args.get('scope')
        token = self._token_manager.get(token, scope)
        return {'data': token.to_dict()}

    def head(self, token):
        scope = request.args.get('scope')
        token = self._token_manager.get(token, scope)
        return '', 204


