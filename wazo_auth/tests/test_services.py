# -*- coding: utf-8 -*-
#
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

from hamcrest import assert_that, calling, equal_to, raises
from mock import ANY, Mock, sentinel as s
from unittest import TestCase

from .. import exceptions, services, database


class TestPolicyService(TestCase):

    def setUp(self):
        self.storage = Mock(database.Storage)
        self.service = services.PolicyService(self.storage)

    def test_create_policy_valid(self):
        name = 'valid'
        desc = 'A Valid description'
        input_and_expected = [
            (
                {'name': name},
                {'uuid': ANY,
                 'name': name,
                 'description': None,
                 'acl_templates': []}
            ),
            (
                {'name': name, 'description': desc},
                {'uuid': ANY,
                 'name': name,
                 'description': desc,
                 'acl_templates': []}
            )
        ]

        for policy_data, expected in input_and_expected:
            policy = self.service.create(policy_data)
            assert_that(policy, equal_to(expected))

    def test_that_invalid_values_raise_a_manager_exception(self):
        names = [
            None,
            True,
            False,
            '',
            42,
        ]

        for name in names:
            assert_that(
                calling(self.service.create).with_args({'name': name}),
                raises(exceptions.InvalidInputException)
            )

        descriptions = [
            True,
            False,
            42,
        ]
        for desc in descriptions:
            body = {'name': 'name', 'description': desc}
            assert_that(
                calling(self.service.create).with_args(body),
                raises(exceptions.InvalidInputException)
            )

        assert_that(
            calling(self.service.create).with_args(None),
            raises(exceptions.InvalidInputException))

    def test_that_invalid_acl_templates_raise_a_manager_exception(self):
        name = 'foobar'
        templates = [
            {'foo': 'bar'},
            42,
            True,
            False,
            None,
            'auth.*',
            [{'foo': 'bar'}],
            [42],
            ['#', False],
            [None],
        ]

        for template in templates:
            assert_that(
                calling(self.service.create).with_args({
                    'name': name,
                    'acl_templates': template
                }), raises(exceptions.InvalidInputException),
                template)

    def test_delete(self):
        self.service.delete(s.policy_uuid)

        self.storage.delete_policy.assert_called_once_with(s.policy_uuid)


class TestUserService(TestCase):

    def setUp(self):
        self.encrypter = Mock(services.PasswordEncrypter)
        self.storage = Mock(database.Storage)
        self.service = services.UserService(self.storage, encrypter=self.encrypter)

    def test_that_new(self):
        params = dict(
            username='foobar',
            password='s3cre7',
            email_address='foobar@example.com',
        )
        expected_db_params = dict(
            username='foobar',
            email_address='foobar@example.com',
            salt=s.salt,
            hash_=s.hash_,
        )
        self.encrypter.encrypt_password.return_value = s.salt, s.hash_

        result = self.service.new_user(**params)

        self.storage.user_create.assert_called_once_with(**expected_db_params)
        assert_that(result, equal_to(self.storage.user_create.return_value))
