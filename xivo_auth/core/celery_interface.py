# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Avencall
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

import logging

from celery import Celery
from celery.utils import LOG_LEVELS
from multiprocessing import Process

logger = logging.getLogger(__name__)


def make_celery(app):
    celery = Celery(app.import_name, broker=app.config['amqp']['uri'])
    celery.conf.update(app.config)
    celery.conf.update(
        CELERY_RESULT_BACKEND=app.config['amqp']['uri'],
        CELERY_ACCEPT_CONTENT=['json'],
        CELERY_TASK_SERIALIZER='json',
        CELERY_RESULT_SERIALIZER='json',
        CELERY_ALWAYS_EAGER=False,
        CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
        CELERYD_LOG_LEVEL=LOG_LEVELS['DEBUG'],  # TODO fix setup_logging to work with string and use the string here
        CELERY_DEFAULT_EXCHANGE_TYPE='topic',
    )

    TaskBase = celery.Task

    class ContextTask(TaskBase):
        abstract = True

        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)

    celery.Task = ContextTask
    return celery


class CeleryInterface(Process):

    def __init__(self, celery):
        self.celery = celery
        super(CeleryInterface, self).__init__()

    def run(self):
        logger.debug('Running celery worker')
        self.celery.worker_main()
