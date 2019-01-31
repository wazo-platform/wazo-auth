# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from hamcrest import assert_that, contains_inanyorder, empty, equal_to
from mock import Mock

from ..helpers import LazyTemplateRenderer, LocalTokenManager


class TestLazyTemplateRenderer(unittest.TestCase):

    def test_render_no_templates(self):
        renderer = LazyTemplateRenderer([], None)

        acls = renderer.render()

        assert_that(acls, empty())

    def test_render_no_substitution(self):
        expected = [
            'confd.user.#',
            'dird.me.#',
        ]
        renderer = LazyTemplateRenderer(expected, None)

        acls = renderer.render()

        assert_that(acls, contains_inanyorder(*expected))

    def test_multi_line_template(self):
        def get():
            return {
                'lines': [1, 42],
            }

        templates = [
            'dird.me.#',
            '{% for line in lines %}confd.lines.{{ line }}.#:{% endfor %}',
        ]
        renderer = LazyTemplateRenderer(templates, get)

        acls = renderer.render()

        expected = [
            'confd.lines.1.#',
            'confd.lines.42.#',
            'dird.me.#',
        ]
        assert_that(acls, contains_inanyorder(*expected))


class TestLocalTokenManager(unittest.TestCase):

    def setUp(self):
        self._token_manager = Mock()
        self._backend = Mock()
        self._user_service = Mock()
        self._user_service.list_users.return_value = [Mock()]

        self.local_token_manager = LocalTokenManager(
            self._backend, self._token_manager, self._user_service
        )

    def test_get_token_first_token(self):
        token = self.local_token_manager.get_token()

        self._token_manager.new_token.assert_called_once_with(
            self._backend.obj, 'wazo-auth', {'expiration': 3600, 'backend': 'wazo_user'})

        assert_that(token, equal_to(self._token_manager.new_token.return_value.token))

    def test_that_a_new_token_is_not_created_at_each_call(self):
        token_1 = self.local_token_manager.get_token()
        token_2 = self.local_token_manager.get_token()

        assert_that(token_1, equal_to(token_2))

    def test_that_a_new_token_does_nothing_when_no_user(self):
        self._user_service.list_users.return_value = []
        token = self.local_token_manager.get_token()

        assert_that(token, equal_to(None))

    def test_that_revoke_token_does_nothing_when_no_token(self):
        self.local_token_manager.revoke_token()

        assert_that(self._token_manager.remove_token.called, equal_to(False))

    def test_that_revoke_revokes_the_token(self):
        token = self.local_token_manager.get_token()

        self.local_token_manager.revoke_token()

        self._token_manager.remove_token.assert_called_once_with(token)
