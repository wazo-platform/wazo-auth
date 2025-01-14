# Copyright 2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import smtplib
from email import utils as email_utils
from email.mime.text import MIMEText

from wazo_auth.interfaces import BaseEmail, EmailDestination

# NOTE(sileht): default socket timeout is None on linux
# Our client http client is 10s, since sending mail is currently synchronous
# we have to be sure we return before the 10s, so we set the SMTP timeout.
SMTP_TIMEOUT = 4


class SMTPEmail(BaseEmail):
    def __init__(self, config: dict):
        self._host = config['smtp']['hostname']
        self._port = config['smtp']['port']

    def send(
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
