# Copyright 2016-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

import requests
import yaml
from openapi_spec_validator import openapi_v2_spec_validator, validate_spec

from .helpers import base

logger = logging.getLogger('openapi_spec_validator')
logger.setLevel(logging.INFO)


@base.use_asset('base')
class TestDocumentation(base.APIIntegrationTest):
    def test_documentation_errors(self):
        api_url = f'http://{self.auth_host}:{self.auth_port}/0.1/api/api.yml'
        api = requests.get(api_url)
        validate_spec(yaml.safe_load(api.text), validator=openapi_v2_spec_validator)
