#!/bin/sh
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

NORMAL_TEMPLATE_FILE="alembic/alembic_template.py.mako"
ACL_TEMPLATE_FILE="alembic/alembic_acl_template.py.mako"
ALEMBIC_ENTRY_POINT="alembic/script.py.mako"
ACL=0

usage () {
    echo "Usage: $0 [-a] <description of the revision>"
    echo "\t-a: Create an ACL migration"
    exit
}

template_file="$NORMAL_TEMPLATE_FILE"

while getopts ":ah" opt; do
    case $opt in
        a)
            template_file="$ACL_TEMPLATE_FILE"
            ;;
        \?)
            usage
            ;;
    esac
done
shift $(expr $OPTIND - 1)

msg="$1"
if [ -z "${msg}" ]; then
    usage
fi

ln -sf "$(pwd)/$template_file" "$(pwd)/$ALEMBIC_ENTRY_POINT"
alembic -c alembic.ini revision -m "$msg"
rm -f "$ALEMBIC_ENTRY_POINT"
