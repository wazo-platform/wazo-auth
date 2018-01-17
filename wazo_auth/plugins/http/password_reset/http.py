# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from flask import request
from xivo.auth_verifier import no_auth
from wazo_auth import http
from wazo_auth.exceptions import UnknownUserException
from .schemas import PasswordResetPostParameters, PasswordResetQueryParameters
from .exceptions import PasswordResetException

logger = logging.getLogger(__name__)


class PasswordReset(http.AuthResource):

    def __init__(self, email_service, user_service):
        self.email_service = email_service
        self.user_service = user_service

    @no_auth
    def get(self):
        args, errors = PasswordResetQueryParameters().load(request.args)
        if errors:
            raise PasswordResetException.from_errors(errors)

        logger.debug('resetting password for %s', args['username'] or args['email_address'])
        try:
            user = self.user_service.delete_password(**args)
        except UnknownUserException:
            # We do not want to leak the information if a user exists or not
            logger.debug('Failed to reset password %s', args)
        else:
            logger.debug('user: %s', user)
            email_address = args['email_address'] or self._extract_email(user)
            if email_address:
                self.email_service.send_reset_email(user['uuid'], user['username'], email_address)
            else:
                logger.debug('No confirmed email %s', args)

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

        logger.debug('changing password for %s', user_uuid)
        self.user_service.change_password(user_uuid, None, args['password'], reset=True)

        return '', 204

    def _extract_email(self, user):
        for email in user['emails']:
            if email['main'] and email['confirmed']:
                return email['address']
        for email in user['emails']:
            if email['confirmed']:
                return email['address']
