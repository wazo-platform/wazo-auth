# Copyright 2017-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import assert_that, has_entries, has_items
from .helpers import fixtures
from .helpers.base import assert_http_error, WazoAuthTestCase
from xivo_test_helpers.hamcrest.uuid_ import uuid_


class TestWazoUserBackend(WazoAuthTestCase):
    @fixtures.http.user_register(
        username='foobar', email_address='foobar@example.com', password='s3cr37'
    )
    def test_token_creation(self, user):
        response = self._post_token(user['username'], 's3cr37', backend='wazo_user')
        assert_that(
            response,
            has_entries(
                token=uuid_(),
                auth_id=user['uuid'],
                xivo_user_uuid=user['uuid'],  # For API compatibility reason
                acls=has_items('confd.#', 'plugind.#'),
                session_uuid=uuid_(),
                metadata=has_entries(
                    pbx_user_uuid=user['uuid'], xivo_user_uuid=user['uuid']
                ),
            ),
        )

        assert_http_error(
            401,
            self._post_token,
            user['username'],
            'not-our-password',
            backend='wazo_user',
        )
        assert_http_error(
            401, self._post_token, 'not-foobar', 's3cr37', backend='wazo_user'
        )

    @fixtures.http.group()
    @fixtures.http.tenant()
    # extra tenant: "master" tenant
    @fixtures.http.user(password='s3cr37')
    def test_token_metadata(self, user, tenant, group):
        top_tenant = self.get_top_tenant()
        self.client.groups.add_user(group['uuid'], user['uuid'])

        token_data = self._post_token(user['username'], 's3cr37', backend='wazo_user')

        assert_that(
            token_data['metadata'],
            has_entries(
                xivo_uuid='the-predefined-xivo-uuid',
                uuid=user['uuid'],
                tenant_uuid=top_tenant['uuid'],
                groups=has_items(has_entries(uuid=group['uuid'])),
            ),
        )

    def test_no_password(self):
        user = self.client.users.new(
            username='foobar', email_address='foobar@example.com'
        )
        try:
            assert_http_error(
                401, self._post_token, user['username'], 'p45sw0rd', backend='wazo_user'
            )
        finally:
            self.client.users.delete(user['uuid'])
