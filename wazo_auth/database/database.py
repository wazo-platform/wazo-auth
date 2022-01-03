# Copyright 2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os

import alembic.config
import alembic.command
import alembic.migration
from sqlalchemy import create_engine

from tenacity import after_log, before_log, retry, stop_after_attempt, wait_fixed

logger = logging.getLogger(__name__)


@retry(
    stop=stop_after_attempt(60 * 5),
    wait=wait_fixed(1),
    before=before_log(logger, logging.INFO),
    after=after_log(logger, logging.WARN),
)
def wait_is_ready(connection):
    try:
        # Try to create session to check if DB is awake
        connection.execute('SELECT 1')
    except Exception as e:
        logger.warning('fail to connect to the database: %s', e)
        raise


def upgrade(uri):
    current_dir = os.path.dirname(__file__)
    config = alembic.config.Config(f'{current_dir}/alembic.ini')
    config.set_main_option('script_location', f'{current_dir}/alembic')
    config.set_main_option('sqlalchemy.url', uri)
    config.set_main_option('configure_logging', 'false')

    logger.info('Upgrading database')
    engine = create_engine(uri)
    wait_is_ready(engine)
    alembic.command.upgrade(config, 'head')
    logger.info('Database upgraded')
