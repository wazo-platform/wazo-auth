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

from UserDict import UserDict
from datetime import datetime, timedelta


class FlatDict(UserDict):

    def __init__(self, original):
        self.data = {}
        for key, value in self.get_pairs('', original):
            self.data[key] = value

    def get_pairs(self, prefix, d):
        for key, value in d.iteritems():
            new_key = '{}{}'.format(prefix, key)
            if not isinstance(value, dict):
                yield new_key, value
            else:
                next_prefix = '{}/'.format(new_key)
                for nested_key, nested_value in self.get_pairs(next_prefix, value):
                    yield nested_key, nested_value


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


def now():
    return datetime.now().isoformat()


def later(seconds):
    delta = timedelta(seconds=seconds)
    t = datetime.now() + delta
    return t.isoformat()
