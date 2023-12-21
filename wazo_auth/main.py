# Copyright 2015-2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import sys

from xivo import xivo_logging
from xivo.config_helper import UUIDNotFound, set_xivo_uuid
from xivo.user_rights import change_user

from wazo_auth.config import get_config
from wazo_auth.controller import Controller
from wazo_auth.database import database

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

    if config['user']:
        change_user(config['user'])

    if config["db_upgrade_on_startup"]:
        database.upgrade(config["db_uri"])

    try:
        set_xivo_uuid(config, logger)
    except UUIDNotFound:
        if config['service_discovery']['enabled']:
            raise

    controller = Controller(config)
    controller.run()


def upgrade_db():
    conf = get_config(sys.argv[1:])
    database.upgrade(conf["db_uri"])
