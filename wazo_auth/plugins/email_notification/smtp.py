# Copyright 2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import smtplib
from email import utils as email_utils
from email.mime.text import MIMEText

from wazo_auth.interfaces import BaseEmailNotification, EmailDestination

# NOTE(sileht): default socket timeout is None on linux
# Our client http client is 10s, since sending mail is currently synchronous
# we have to be sure we return before the 10s, so we set the SMTP timeout.
SMTP_TIMEOUT = 4


class SMTPEmail(BaseEmailNotification):
    def __init__(self, *args, **kwargs) -> None:
        if 'config' not in kwargs:
            raise Exception("Missing 'config' argument to initialize plugin")
        if 'template_formatter' not in kwargs:
            raise Exception(
                "Missing 'template_formatter' argument to initialize plugin"
            )

        config = kwargs['config']
        self._formatter = kwargs['template_formatter']
        self._host = config['smtp']['hostname']
        self._port = config['smtp']['port']
        self._confirmation_from = EmailDestination(
            config['email_confirmation_from_name'],
            config['email_confirmation_from_address'],
        )
        self._password_reset_from = EmailDestination(
            config['password_reset_from_name'], config['password_reset_from_address']
        )

    def send_confirmation(self, context: dict) -> None:
        body = self._formatter.format_confirmation_email(context)
        subject = self._formatter.format_confirmation_subject(context)
        to = EmailDestination(context['username'], context['email_address'])
        self._send(to, self._confirmation_from, subject, body)

    def send_password_reset(self, context: dict) -> None:
        body = self._formatter.format_password_reset_email(context)
        subject = self._formatter.format_password_reset_subject(context)
        to = EmailDestination(context['username'], context['email_address'])
        self._send(to, self._password_reset_from, subject, body)

    def _send(
        self,
        to: EmailDestination,
        from_: EmailDestination,
        subject: str,
        body: str,
    ) -> None:
        msg = MIMEText(body)
        msg['To'] = email_utils.formataddr(to)
        msg['From'] = email_utils.formataddr(from_)
        msg['Subject'] = subject

        with smtplib.SMTP(self._host, self._port, timeout=SMTP_TIMEOUT) as server:
            server.sendmail(from_.address, [to.address], msg.as_string())
