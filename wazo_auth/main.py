# Copyright 2015-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import logging

from xivo import xivo_logging
from xivo.config_helper import set_xivo_uuid, UUIDNotFound
from xivo.user_rights import change_user

from wazo_auth.config import get_config
from wazo_auth.controller import Controller

SPAMMY_LOGGERS = ['urllib3', 'Flask-Cors', 'amqp', 'kombu']

logger = logging.getLogger(__name__)


def main():
    xivo_logging.silence_loggers(SPAMMY_LOGGERS, logging.WARNING)

    config = get_config(sys.argv[1:])

    xivo_logging.setup_logging(
        config['log_filename'],
        debug=config['debug'],
        log_level=config['log_level'],
    )

    user = config.get('user')
    if user:
        change_user(user)

    try:
        set_xivo_uuid(config, logger)
    except UUIDNotFound:
        if config['service_discovery']['enabled']:
            raise

    controller = Controller(config)
    controller.run()
