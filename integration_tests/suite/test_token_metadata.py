# Copyright 2017-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import assert_that, has_entries
from .helpers import fixtures, base


@base.use_asset('base')
class TestDefaultTokenMetadata(base.APIIntegrationTest):
    @fixtures.http.user(username='foobar', password='s3cr37', purpose='user')
    @fixtures.http.group()
    def test_user_purpose_metadata(self, user, group):
        self.client.groups.add_user(group['uuid'], user['uuid'])

        token_data = self._post_token(user['username'], 's3cr37')

        assert_that(
            token_data['metadata'],
            has_entries(
                uuid=user['uuid'],
                tenant_uuid=self.top_tenant_uuid,
                auth_id=user['uuid'],
                pbx_user_uuid=user['uuid'],
                xivo_uuid='the-predefined-xivo-uuid',
                purpose='user',
            ),
        )

    @fixtures.http.user(username='foobar', password='s3cr37', purpose='internal')
    def test_internal_purpose_metadata(self, user):
        token_data = self._post_token(user['username'], 's3cr37')

        assert_that(
            token_data['metadata'],
            has_entries(
                uuid=user['uuid'],
                tenant_uuid=self.top_tenant_uuid,
                auth_id=user['uuid'],
                pbx_user_uuid=None,
                xivo_uuid='the-predefined-xivo-uuid',
                purpose='internal',
            ),
        )

    @fixtures.http.user(username='foobar', password='s3cr37', purpose='external_api')
    def test_external_api_purpose_metadata(self, user):
        token_data = self._post_token(user['username'], 's3cr37')

        assert_that(
            token_data['metadata'],
            has_entries(
                uuid=user['uuid'],
                tenant_uuid=self.top_tenant_uuid,
                auth_id=user['uuid'],
                pbx_user_uuid=None,
                xivo_uuid='the-predefined-xivo-uuid',
                purpose='external_api',
            ),
        )
