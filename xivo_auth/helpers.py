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


def values_to_dict(values):
    tree = {}

    for item in values:
        complete_key = item['Key']
        parts = complete_key.split('/')
        length = len(parts)
        t = tree
        for n, part in enumerate(parts):
            default = {} if n < length - 1 else item['Value']
            t = t.setdefault(part, default)

    return tree
