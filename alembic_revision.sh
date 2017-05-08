#!/bin/sh
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
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
