# Copyright 2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from wazo_auth import BaseEmailNotification

logger = logging.getLogger(__name__)


class Plugin(BaseEmailNotification):
    def __init__(self, *args, **kwargs):
        logger.info('email_notification_logger: __init__')

    def send_confirmation(self, context):
        logger.info(
            'email_notification_logger,send_confirmation,%s',
            context,
        )

    def send_password_reset(self, context):
        logger.info(
            'email_notification_logger,send_password_reset,%s',
            context,
        )
