# Copyright 2019-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime
from unittest import TestCase

from hamcrest import assert_that, is_

from wazo_auth.config import _DEFAULT_CONFIG

from ..saml import SamlAuthContext, SAMLService


class TestSAMLService(TestCase):
    def setUp(self):
        self.lifetime = 10
        self.config = _DEFAULT_CONFIG
        self.config['saml']['saml_session_lifetime_seconds'] = self.lifetime
        self.service = SAMLService(self.config)

    def test_clean_pending_requests(self):
        expired_date: datetime = datetime.fromisoformat('2000-01-01 00:00:02')
        expired: SamlAuthContext = SamlAuthContext(
            'saml_id', 'some_url', 'some_tenant', None, None, expired_date
        )

        pending_date: datetime = datetime.fromisoformat('2000-01-01 00:00:01')
        pending: SamlAuthContext = SamlAuthContext(
            'saml_yd', 'some_url', 'some_tenant', None, None, pending_date
        )

        self.service._outstanding_requests = {'id1': expired, 'id2': pending}

        now: datetime = datetime.fromisoformat('2000-01-01 00:00:11')
        self.service.clean_pending_requests(now)

        assert_that(self.service._outstanding_requests, is_({'id2': pending}))
