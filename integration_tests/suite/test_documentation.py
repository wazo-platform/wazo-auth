# Copyright 2016-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import requests
import yaml

from openapi_spec_validator import validate_v2_spec

from .helpers.base import BaseTestCase

logger = logging.getLogger('openapi_spec_validator')
logger.setLevel(logging.INFO)


class TestDocumentation(BaseTestCase):

    asset = 'documentation'

    def test_documentation_errors(self):
        port = self.service_port(9497, 'auth')
        api_url = 'http://localhost:{port}/0.1/api/api.yml'.format(port=port)
        api = requests.get(api_url)
        validate_v2_spec(yaml.safe_load(api.text))
