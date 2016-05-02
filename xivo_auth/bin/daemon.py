# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Avencall
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import sys
import logging
import xivo_dao

from xivo import xivo_logging
from xivo.config_helper import set_xivo_uuid, UUIDNotFound
from xivo.daemonize import pidfile_context
from xivo.user_rights import change_user
from xivo_auth.config import get_config
from xivo_auth.controller import Controller

SPAMMY_LOGGERS = ['urllib3', 'Flask-Cors', 'amqp', 'kombu', 'celery']

logger = logging.getLogger(__name__)


def main():
    xivo_logging.silence_loggers(SPAMMY_LOGGERS, logging.WARNING)

    config = get_config(sys.argv[1:])

    xivo_logging.setup_logging(config['log_filename'], config['foreground'],
                               config['debug'], config['log_level'])

    user = config.get('user')
    if user:
        change_user(user)

    try:
        set_xivo_uuid(config, logger)
    except UUIDNotFound:
        if config['service_discovery']['enabled']:
            raise

    xivo_dao.init_db_from_config(config)

    controller = Controller(config)
    with pidfile_context(config['pid_filename'], config['foreground']):
        try:
            controller.run()
        except KeyboardInterrupt:
            pass
