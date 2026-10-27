# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import subprocess
import sys
import textwrap
from unittest import TestCase

from hamcrest import assert_that, equal_to

# A fresh interpreter: this test process may already have imported the Microsoft
# plugin, which sets the same oauthlib variables.
SCRIPT = textwrap.dedent(
    '''
    import sys
    from wazo_auth.plugins.external_auth.salesforce import http
    from wazo_auth.plugins.external_auth.salesforce.tests.helpers import (
        TOKEN_URL, FakeTokenEndpoint, salesforce_token_body,
    )
    from requests_oauthlib import OAuth2Session

    assert 'wazo_auth.plugins.external_auth.microsoft.http' not in sys.modules
    session = OAuth2Session('id', scope=['api'], redirect_uri='https://r.example.com')
    with FakeTokenEndpoint((200, salesforce_token_body())).serving():
        token = http.fetch_first_token(session, TOKEN_URL, 'secret', 'code', 'v' * 43)
    print(' '.join(token['scope']))
    '''
)


class TestReturnedScopeIsKept(TestCase):
    def test_a_scope_other_than_the_requested_one_is_not_refused(self):
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith('OAUTHLIB_')
        }

        result = subprocess.run(
            [sys.executable, '-c', SCRIPT],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert_that(result.returncode, equal_to(0), result.stderr)
        assert_that(result.stdout.strip(), equal_to('api refresh_token id'))
