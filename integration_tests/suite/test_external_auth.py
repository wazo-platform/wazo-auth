# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from uuid import uuid4
from hamcrest import (assert_that, equal_to)
from .helpers import base, fixtures


class TestExternalAuthAPI(base.MockBackendTestCase):

    asset = 'external_auth'

    @fixtures.http_user()
    def test_create(self, user):
        original_data = {'secret': str(uuid4())}

        result = self.client.external.create('foo', user['uuid'], original_data)
        assert_that(result, equal_to(original_data))

        data = self.client.external.get('foo', user['uuid'])
        assert_that(data, equal_to(original_data))

        base.assert_http_error(404, self.client.external.create, 'notfoo', user['uuid'], original_data)
        base.assert_http_error(404, self.client.external.create, 'foo', base.UNKNOWN_UUID, original_data)
