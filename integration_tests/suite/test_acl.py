# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import (
    assert_that,
    has_entry,
    has_items,
)
from .helpers.base import (
    WazoAuthTestCase,
)
from .helpers import fixtures

MULTI_ACL_TEMPLATE = '{% for resource in ("users", "lines") %}confd.{{ resource }}:{% endfor %}'


class TestACL(WazoAuthTestCase):

    @fixtures.http.policy(name='multple-acl-in-one-template', acl_templates=[MULTI_ACL_TEMPLATE])
    @fixtures.http.user(password='some-password')
    def test_acl_template_loop_for(self, user, policy):
        self.client.users.add_policy(user['uuid'], policy['uuid'])
        token = self._post_token(user['username'], 'some-password')['token']

        response = self._get_token(token)

        assert_that(response, has_entry('acls', has_items('confd.users', 'confd.lines')))
