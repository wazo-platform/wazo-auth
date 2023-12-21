# Copyright 2017-2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import assert_that, has_entries

from .helpers import base, fixtures


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


@base.use_asset('metadata')
class TestUserAdminStatusMetadata(base.MetadataIntegrationTest):
    @fixtures.http.user(username='foobar', password='s3cr37', purpose='user')
    def test_admin_status_metadata_when_not_admin(self, user):
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
                admin=False,
            ),
        )

    @fixtures.http.user(username='foobar', password='s3cr37', purpose='user')
    def test_admin_status_metadata_when_admin(self, user):
        admin_policy = self.client.policies.get('wazo_default_admin_policy')
        self.client.users.add_policy(user['uuid'], admin_policy['uuid'])

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
                admin=True,
            ),
        )

    @fixtures.http.user(username='foobar', password='s3cre37', purpose='user')
    def test_admin_status_metadata_when_in_admin_group(self, user):
        group = self.client.groups.list(search='wazo_default_admin_group')['items'][0]
        self.client.groups.add_user(group['uuid'], user['uuid'])

        try:
            token_data = self._post_token(user['username'], 's3cre37')
        finally:
            self.client.groups.remove_user(group['uuid'], user['uuid'])

        assert_that(
            token_data['metadata'],
            has_entries(
                uuid=user['uuid'],
                tenant_uuid=self.top_tenant_uuid,
                auth_id=user['uuid'],
                pbx_user_uuid=user['uuid'],
                xivo_uuid='the-predefined-xivo-uuid',
                purpose='user',
                admin=True,
            ),
        )
