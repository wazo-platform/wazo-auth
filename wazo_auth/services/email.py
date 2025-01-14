# Copyright 2018-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time

from wazo_auth.interfaces import EmailDestination
from wazo_auth.services.helpers import BaseService


class EmailService(BaseService):
    def __init__(self, dao, config, template_formatter, driver):
        super().__init__(dao)
        self._formatter = template_formatter
        self._driver = driver
        self._confirmation_token_expiration = config['email_confirmation_expiration']
        self._reset_token_expiration = config['password_reset_expiration']
        self._confirmation_from = EmailDestination(
            config['email_confirmation_from_name'],
            config['email_confirmation_from_address'],
        )
        self._password_reset_from = EmailDestination(
            config['password_reset_from_name'], config['password_reset_from_address']
        )

    def confirm(self, email_uuid):
        self._dao.email.confirm(email_uuid)

    def send_confirmation_email(
        self, username, email_uuid, email_address, connection_params
    ):
        template_context = dict(connection_params)
        template_context.update(
            {
                'token': self._new_email_confirmation_token(email_uuid),
                'username': username,
                'email_uuid': email_uuid,
                'email_address': email_address,
            }
        )

        body = self._formatter.format_confirmation_email(template_context)
        subject = self._formatter.format_confirmation_subject(template_context)
        to = EmailDestination(username, email_address)
        self._driver.send(to, self._confirmation_from, subject, body)

    def send_reset_email(self, user_uuid, username, email_address, connection_params):
        template_context = dict(connection_params)
        template_context.update(
            {
                'token': self._new_email_reset_token(user_uuid),
                'username': username,
                'user_uuid': user_uuid,
                'email_address': email_address,
            }
        )

        body = self._formatter.format_password_reset_email(template_context)
        subject = self._formatter.format_password_reset_subject(template_context)
        to = EmailDestination(username, email_address)
        self._driver.send(to, self._confirmation_from, subject, body)

    def _new_email_confirmation_token(self, email_uuid):
        acl = f'auth.emails.{email_uuid}.confirm.edit'
        return self._new_generic_token(self._confirmation_token_expiration, acl)

    def _new_email_reset_token(self, user_uuid):
        acl = f'auth.users.password.reset.{user_uuid}.create'
        return self._new_generic_token(self._reset_token_expiration, acl)

    def _new_generic_token(self, expiration, *acl):
        t = time.time()
        token_payload = {
            'auth_id': 'wazo-auth',
            'pbx_user_uuid': None,
            'xivo_uuid': None,
            'expire_t': t + expiration,
            'issued_t': t,
            'acl': acl,
            'user_agent': 'wazo-auth-email-reset',
            'remote_addr': '',
        }
        session_payload = {}
        token_uuid, session_uuid = self._dao.token.create(
            token_payload, session_payload
        )
        return token_uuid
