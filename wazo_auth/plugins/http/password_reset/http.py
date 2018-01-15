# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from flask import request
from xivo.auth_verifier import no_auth
from wazo_auth import http
from wazo_auth.exceptions import UnknownUserException
from .schemas import (PasswordResetPostParameters, PasswordResetQueryParameters)
from .exceptions import PasswordResetException

logger = logging.getLogger(__name__)


class PasswordReset(http.AuthResource):

    def __init__(self, user_service):
        self.user_service = user_service

    @no_auth
    def get(self):
        args, errors = PasswordResetQueryParameters().load(request.args)
        if errors:
            raise PasswordResetException.from_errors(errors)

        logger.debug('resetting password for %s', args['username'] or args['email_address'])
        try:
            self.user_service.delete_password(**args)
        except UnknownUserException:
            # We do not want to leak the information if a user exists or not
            pass

        return '', 204

    @no_auth
    def post(self):

        @self.auth_verifier.verify_token
        @http.required_acl('auth.users.password.reset.{user_uuid}.create')
        def verify_token(user_uuid):
            # This function will raise an exception returning a 401 if the token
            # does not have the necessary acl to change the password
            return

        user_uuid = request.args.get('user_uuid')
        verify_token(user_uuid=user_uuid)

        args, errors = PasswordResetPostParameters().load(request.get_json())
        if errors:
            raise PasswordResetException.from_errors(errors)

        logger.debug('changing password for %s: %s', user_uuid, args)

        return '', 204
