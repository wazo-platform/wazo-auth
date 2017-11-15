# -*- coding: utf-8 -*-
# Copyright 2016-2017 The Wazo Authors  (see the AUTHORS file)
#
# SPDX-License-Identifier: GPL-3.0+

import requests
import pprint

from hamcrest import assert_that, empty

from .helpers.base import BaseTestCase


class TestDocumentation(BaseTestCase):

    asset = 'documentation'
    service = 'auth'

    def test_documentation_errors(self):
        api_url = 'https://auth:9497/0.1/api/api.yml'
        self.validate_api(api_url)

    def validate_api(self, url):
        port = self.service_port(8080, 'swagger-validator')
        validator_url = u'http://localhost:{port}/debug'.format(port=port)
        response = requests.get(validator_url, params={'url': url})
        assert_that(response.json(), empty(), pprint.pformat(response.json()))
