# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import requests
from hamcrest import assert_that, contains_string, equal_to

from .helpers import base


@base.use_asset('base')
class TestMetrics(base.APIIntegrationTest):
    def test_metrics_without_token(self):
        self.client.status.check()

        response = requests.get(f'http://127.0.0.1:{self.auth_port()}/0.1/metrics')

        assert_that(response.status_code, equal_to(200))
        assert_that(
            response.text,
            contains_string('flask_http_request_total{method="HEAD",status="200"}'),
        )
        assert_that(
            response.text,
            contains_string(
                'flask_http_request_duration_seconds_count'
                '{endpoint="statuslist",method="HEAD",status="200"}'
            ),
        )
