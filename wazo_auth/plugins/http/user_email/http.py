# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from wazo_auth import exceptions, http

from .exceptions import EmailAlreadyConfirmedException

logger = logging.getLogger(__name__)


class UserEmailConfirm(http.AuthResource):

    def __init__(self, email_service, user_service):
        self.email_service = email_service
        self.user_service = user_service

    @http.required_acl('auth.users.{user_uuid}.emails.{email_uuid}.confirm.read')
    def get(self, user_uuid, email_uuid):
        logger.debug('sending a new email confirmation user_uuid: %s email_uuid: %s',
                     user_uuid, email_uuid)

        user = self.user_service.get_user(user_uuid)
        email = self._get_email_details(user, email_uuid)

        username, uuid, address = user['username'], str(email_uuid), email['address']
        self.email_service.send_confirmation_email(username, uuid, address)

        return '', 204

    def _get_email_details(self, user, email_uuid):
        emails = [email for email in user['emails'] if email['uuid'] == str(email_uuid)]
        if not emails:
            raise exceptions.UnknownEmailException(email_uuid)

        for email in emails:
            if email['confirmed']:
                raise EmailAlreadyConfirmedException(email_uuid)

            return email
