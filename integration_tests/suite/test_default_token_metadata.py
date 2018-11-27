# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from hamcrest import (
    assert_that,
    contains,
    has_entries,
)
from .helpers import fixtures
from .helpers.base import WazoAuthTestCase


class TestDefaultTokenMetadata(WazoAuthTestCase):

    def setUp(self):
        super().setUp()
        self.tenant_uuid = self.get_top_tenant()['uuid']

    @fixtures.http_group()
    @fixtures.http_user(password='s3cr37', purpose='user')
    def test_token_metadata(self, user, group):
        self.client.groups.add_user(group['uuid'], user['uuid'])

        token_data = self._post_token(user['username'], 's3cr37')

        assert_that(token_data['metadata'], has_entries(
            uuid=user['uuid'],
            tenant_uuid=self.tenant_uuid,
            groups=contains(has_entries(uuid=group['uuid'])),

            auth_id=user['uuid'],
            username=user['username'],
            xivo_uuid='the-predefined-xivo-uuid',
            xivo_user_uuid=user['uuid'],
        ))

    @fixtures.http_user(password='s3cr37', purpose='internal')
    def test_internal_purpose_metadata(self, user):
        token_data = self._post_token(user['username'], 's3cr37')

        assert_that(token_data['metadata'], has_entries(
            uuid=user['uuid'],
            tenant_uuid=self.tenant_uuid,

            auth_id=user['uuid'],
            username=user['username'],
            xivo_uuid='the-predefined-xivo-uuid',
            xivo_user_uuid=None,
        ))

    @fixtures.http_user(password='s3cr37', purpose='external_api')
    def test_external_api_purpose_metadata(self, user):
        token_data = self._post_token(user['username'], 's3cr37')

        assert_that(token_data['metadata'], has_entries(
            uuid=user['uuid'],
            tenant_uuid=self.tenant_uuid,

            auth_id=user['uuid'],
            username=user['username'],
            xivo_uuid='the-predefined-xivo-uuid',
            xivo_user_uuid=None,
        ))
