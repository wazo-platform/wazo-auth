# Copyright 2015-2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import sys

from xivo import xivo_logging
from xivo.config_helper import UUIDNotFound, set_xivo_uuid
from xivo.user_rights import change_user

from wazo_auth.config import VALID_ROLES, get_config
from wazo_auth.controller import Controller
from wazo_auth.database import database

SPAMMY_LOGGERS = ['urllib3', 'Flask-Cors', 'amqp', 'kombu']

logger = logging.getLogger(__name__)


def main():
    xivo_logging.silence_loggers(SPAMMY_LOGGERS, logging.WARNING)

    try:
        config = get_config(sys.argv[1:])
    except ValueError as e:
        print(f'invalid configuration: {e}', file=sys.stderr)  # journald gets stderr
        sys.exit(os.EX_CONFIG)  # 78: matches RestartPreventExitStatus in the units

    xivo_logging.setup_logging(
        config['log_filename'],
        debug=config['debug'],
        log_level=config['log_level'],
    )

    if set(config['roles']) != set(VALID_ROLES):
        logger.info('Starting wazo-auth with roles: %s', ', '.join(config['roles']))

    if config['user']:
        change_user(config['user'])

    if config["db_upgrade_on_startup"]:
        if 'init' in config['roles']:
            database.upgrade(
                config["db_uri"],
                lock_timeout=config['db_connect_retry_timeout_seconds'],
            )
        else:
            logger.warning(
                'db_upgrade_on_startup is enabled but this instance has '
                'no init role: skipping'
            )

    try:
        set_xivo_uuid(config, logger)
    except UUIDNotFound:
        if config['service_discovery']['enabled']:
            raise

    controller = Controller(config)
    controller.run()


def upgrade_db():
    try:
        conf = get_config(sys.argv[1:])
    except ValueError as e:
        print(f'invalid configuration: {e}', file=sys.stderr)  # apt gets stderr
        sys.exit(os.EX_CONFIG)  # 78: same contract as main()

    database.upgrade(
        conf["db_uri"],
        lock_timeout=conf['db_connect_retry_timeout_seconds'],
    )
