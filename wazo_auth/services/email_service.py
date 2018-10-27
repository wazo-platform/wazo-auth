# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import time
import smtplib

from collections import namedtuple
from email import utils as email_utils
from email.mime.text import MIMEText

from wazo_auth.services.helpers import BaseService

EmailDestination = namedtuple('EmailDestination', ['name', 'address'])


class EmailService(BaseService):

    def __init__(self, dao, tenant_uuid, config, template_formatter):
        super().__init__(dao, tenant_uuid)
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
            config['password_reset_from_name'],
            config['password_reset_from_address'],
        )

    def confirm(self, email_uuid):
        self._dao.email.confirm(email_uuid)

    def send_confirmation_email(self, username, email_uuid, email_address):
        template_context = {
            'token': self._new_email_confirmation_token(email_uuid),
            'username': username,
            'email_uuid': email_uuid,
            'email_address': email_address,
        }

        body = self._formatter.format_confirmation_email(template_context)
        subject = self._formatter.format_confirmation_subject(template_context)
        to = EmailDestination(username, email_address)
        self._send_msg(to, self._confirmation_from, subject, body)

    def send_reset_email(self, user_uuid, username, email_address):
        template_context = {
            'token': self._new_email_reset_token(user_uuid),
            'username': username,
            'user_uuid': user_uuid,
            'email_address': email_address,
        }

        body = self._formatter.format_password_reset_email(template_context)
        subject = self._formatter.format_password_reset_subject(template_context)
        to = EmailDestination(username, email_address)
        self._send_msg(to, self._confirmation_from, subject, body)

    def _send_msg(self, to, from_, subject, body):
        msg = MIMEText(body)
        msg['To'] = email_utils.formataddr(to)
        msg['From'] = email_utils.formataddr(from_)
        msg['Subject'] = subject

        server = smtplib.SMTP(self._smtp_host, self._smtp_port)
        try:
            server.sendmail(from_.address, [to.address], msg.as_string())
        finally:
            server.close()

    def _new_email_confirmation_token(self, email_uuid):
        acl = 'auth.emails.{}.confirm.edit'.format(email_uuid)
        return self._new_generic_token(self._confirmation_token_expiration, acl)

    def _new_email_reset_token(self, user_uuid):
        acl = 'auth.users.password.reset.{}.create'.format(user_uuid)
        return self._new_generic_token(self._reset_token_expiration, acl)

    def _new_generic_token(self, expiration, *acls):
        t = time.time()
        token_payload = {
            'auth_id': 'wazo-auth',
            'xivo_user_uuid': None,
            'xivo_uuid': None,
            'expire_t': t + expiration,
            'issued_t': t,
            'acls': acls,
        }
        return self._dao.token.create(token_payload)
