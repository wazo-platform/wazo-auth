# Copyright 2018-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import smtplib
import time
from collections import namedtuple
from email import utils as email_utils
from email.mime.text import MIMEText

from wazo_auth.services.helpers import BaseService

EmailDestination = namedtuple('EmailDestination', ['name', 'address'])

# NOTE(sileht): default socket timeout is None on linux
# Our client http client is 10s, since sending mail is currently synchronous
# we have to be sure we return before the 10s, so we set the SMTP timeout.
SMTP_TIMEOUT = 4


class EmailService(BaseService):
    def __init__(self):
        self.dao = None
        self.tenant_uuid = None

    def load(self, dependencies):
        dao = dependencies['dao']
        template_formatter = dependencies['template_formatter']
        config = dependencies['config']

        super().__init__(dao)
        self._formatter = template_formatter
        self._smtp_host = config['smtp']['hostname']
        self._smtp_port = config['smtp']['port']
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
        self._send_msg(to, self._confirmation_from, subject, body)

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
        self._send_msg(to, self._password_reset_from, subject, body)

    def _send_msg(self, to, from_, subject, body):
        msg = MIMEText(body)
        msg['To'] = email_utils.formataddr(to)
        msg['From'] = email_utils.formataddr(from_)
        msg['Subject'] = subject

        with smtplib.SMTP(
            self._smtp_host, self._smtp_port, timeout=SMTP_TIMEOUT
        ) as server:
            server.sendmail(from_.address, [to.address], msg.as_string())

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
