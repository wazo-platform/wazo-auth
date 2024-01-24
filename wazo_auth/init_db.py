# Copyright 2016-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import sys
import time

import psycopg2
from xivo import db_helper
from xivo.user_rights import change_user
from xivo.xivo_logging import setup_logging


def _parse_cli_args(args):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--user',
        action='store',
        help="The system user to use to connect to postgresql and create the user and database",
    )
    parser.add_argument(
        '--pg_db_uri',
        action='store',
        default='postgresql:///postgres',
        help="The DSN to connect to the postgres DB as an superuser",
    )
    parser.add_argument(
        '--auth_db_uri',
        action='store',
        default='postgresql:///asterisk',
        help="The DSN to connect to the auth DB as an superuser",
    )
    parser.add_argument(
        '--db',
        action='store',
        default='asterisk',
        help="The database name that will be created",
    )
    parser.add_argument(
        '--owner',
        action='store',
        default='asterisk',
        help="The database user that will be created and that will own the database",
    )
    parser.add_argument(
        '--password',
        action='store',
        default='proformatique',
        help="The password that will be assigned to the created user",
    )
    return parser.parse_args(args)


def main():
    setup_logging('/dev/null', debug=False)
    args = _parse_cli_args(sys.argv[1:])

    if args.user:
        change_user(args.user)

    for _ in range(40):
        try:
            conn = psycopg2.connect(args.pg_db_uri)
            break
        except psycopg2.OperationalError:
            time.sleep(0.25)
    else:
        print('Failed to connect to postgres', file=sys.stderr)
        sys.exit(1)

    conn.autocommit = True
    with conn:
        with conn.cursor() as cursor:
            if not db_helper.db_user_exists(cursor, args.owner):
                db_helper.create_db_user(cursor, args.owner, args.password)
            if not db_helper.db_exists(cursor, args.db):
                db_helper.create_db(cursor, args.db, args.owner)

    conn = psycopg2.connect(args.auth_db_uri)
    with conn:
        with conn.cursor() as cursor:
            db_helper.create_db_extensions(cursor, ['uuid-ossp'])
