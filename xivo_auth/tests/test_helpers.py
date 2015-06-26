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

import unittest

from ..helpers import values_to_dict

from hamcrest import assert_that, equal_to


class TestValuesToDict(unittest.TestCase):

    def test(self):
        values = [{u'LockIndex': 0,
                   u'ModifyIndex': 11,
                   u'Value': '2015-05-26T17:17:36.149121',
                   u'Flags': 0,
                   u'Key': u'xivo/xivo-auth/tokens/a01c036d-54e5-9095-e4ab-5fd1edc232f1/expires_at',
                   u'CreateIndex': 11},
                  {u'LockIndex': 0,
                   u'ModifyIndex': 8,
                   u'Value': '2015-05-26T17:17:26.149083',
                   u'Flags': 0,
                   u'Key': u'xivo/xivo-auth/tokens/a01c036d-54e5-9095-e4ab-5fd1edc232f1/issued_at',
                   u'CreateIndex': 8},
                  {u'LockIndex': 0,
                   u'ModifyIndex': 9,
                   u'Value': 'a01c036d-54e5-9095-e4ab-5fd1edc232f1',
                   u'Flags': 0,
                   u'Key': u'xivo/xivo-auth/tokens/a01c036d-54e5-9095-e4ab-5fd1edc232f1/token',
                   u'CreateIndex': 9},
                  {u'LockIndex': 0,
                   u'ModifyIndex': 10,
                   u'Value': 'a-mocked-uuid',
                   u'Flags': 0,
                   u'Key': u'xivo/xivo-auth/tokens/a01c036d-54e5-9095-e4ab-5fd1edc232f1/auth_id',
                   u'CreateIndex': 10}]

        result = values_to_dict(values)
        expected = {
            'xivo': {
                'xivo-auth': {
                    'tokens': {
                        'a01c036d-54e5-9095-e4ab-5fd1edc232f1': {
                            'expires_at': '2015-05-26T17:17:36.149121',
                            'issued_at': '2015-05-26T17:17:26.149083',
                            'token': 'a01c036d-54e5-9095-e4ab-5fd1edc232f1',
                            'auth_id': 'a-mocked-uuid'}}}}}

        assert_that(result, equal_to(expected))
