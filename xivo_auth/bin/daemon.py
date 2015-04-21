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
from xivo_auth.main import create_app
from xivo_auth.core import plugin_manager
from xivo_auth.core.celery_interface import make_celery, CeleryInterface
from xivo_auth.config import load_config
import click
from pwd import getpwnam
import os


@click.command()
@click.option('--config', default='/etc/xivo-auth/config.yml', help='Configuration file.')
@click.option('--user', default=None)
def main(config, user):
    logger = logging.getLogger(__name__)

    if user:
        change_user(user)

    application = create_app()
    application.config.update(load_config(config))
    make_celery(application)

    plugin_manager.load_plugins(application)

    celery_interface = CeleryInterface()
    celery_interface.start()

    application.run(application.config["APP_LISTEN"],
                    application.config["APP_PORT"])

    celery_interface.join()


def change_user(user):
    try:
        uid = getpwnam(user).pw_uid
        gid = getpwnam(user).pw_gid
    except KeyError:
        raise Exception('Unknown user {user}'.format(user=user))

    try:
        os.setgid(gid)
        os.setuid(uid)
    except OSError as e:
        raise Exception('Could not change owner to user {user}: {error}'.format(user=user, error=e))


if __name__ == '__main__':
    main()
