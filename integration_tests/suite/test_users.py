# Copyright 2017-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime
import json
import requests
from hamcrest import (
    assert_that,
    calling,
    contains,
    contains_inanyorder,
    contains_string,
    empty,
    equal_to,
    is_not,
    has_entries,
    has_item,
    has_items,
    has_key,
    not_,
)
from wazo_test_helpers import until
from wazo_test_helpers.hamcrest.uuid_ import uuid_
from wazo_test_helpers.hamcrest.raises import raises
from .helpers import fixtures, base
from .helpers.constants import UNKNOWN_UUID
from .helpers.base import assert_http_error, assert_no_error


@base.use_asset('base')
class TestUsers(base.APIIntegrationTest):
    @fixtures.http.user_register()
    def test_delete(self, alice):
        with self.client_in_subtenant() as (client, bob, sub_tenant):
            assert_http_error(404, client.users.delete, alice['uuid'])
            assert_http_error(
                401,
                client.users.delete,
                alice['uuid'],
                tenant_uuid=self.top_tenant_uuid,
            )
            assert_no_error(self.client.users.delete, bob['uuid'])

        assert_http_error(404, self.client.users.delete, UNKNOWN_UUID)
        assert_no_error(self.client.users.delete, alice['uuid'])
        assert_http_error(404, self.client.users.delete, alice['uuid'])

    @fixtures.http.user(
        username='foobar', password='foobar', email_address='foobar@example.com'
    )
    @fixtures.http.user(
        username='foobaz', password='foobaz', email_address='foobaz@example.com'
    )
    def test_password_reset_does_not_disable_old_password(self, foobar, foobaz):
        assert_no_error(self.client.users.reset_password, username='unknown')
        assert_no_error(self.client.users.reset_password, email='unknown@example.com')
        assert_http_error(
            400,
            self.client.users.reset_password,
            username='foobar',
            email='foobar@example.com',
        )

        self.client.users.reset_password(username='foobar')

        user_client = self.make_auth_client('foobar', 'foobar')
        assert_no_error(user_client.token.new, 'wazo_user')

        self.client.users.reset_password(email='foobaz@example.com')

        user_client = self.make_auth_client('foobaz', 'foobaz')
        assert_no_error(user_client.token.new, 'wazo_user')

    def test_post_no_token(self):
        args = {
            'username': 'foobar',
            'firstname': 'Alice',
            'email_address': 'foobar@example.com',
            'password': 's3cr37',
        }

        url = 'http://{}:{}/0.1/users'.format(self.auth_host, self.auth_port)
        result = requests.post(
            url,
            headers={'Content-Type': 'application/json'},
            data=json.dumps(args),
            verify=False,
        )
        assert_that(result.status_code, equal_to(401))

    @fixtures.http.tenant(name='isolated')
    def test_post_with_top_tenant_admin(self, isolated):
        args = {
            'username': 'foobar',
            'firstname': 'Alice',
            'email_address': 'foobar@example.com',
            'password': 's3cr37',
        }

        # User created in our own tenant
        with self.user(self.client, **args) as user:
            assert_that(user, not_(has_key('password')))
            assert_that(
                user,
                has_entries(
                    uuid=uuid_(),
                    username='foobar',
                    firstname='Alice',
                    lastname=None,
                    enabled=True,
                    tenant_uuid=self.top_tenant_uuid,
                    emails=contains_inanyorder(
                        has_entries(
                            uuid=uuid_(),
                            address='foobar@example.com',
                            main=True,
                            confirmed=True,
                        )
                    ),
                ),
            )

            # TODO move this assertion to the user tenant tests
            tenants = self.client.users.get_tenants(user['uuid'])
            assert_that(
                tenants['items'], has_items(has_entries(uuid=self.top_tenant_uuid))
            )

            wazo_all_users_group = self.client.groups.list(
                name=f'wazo-all-users-tenant-{self.top_tenant_uuid}',
                tenant_uuid=self.top_tenant_uuid,
            )['items'][0]
            wazo_all_users_group_members = self.client.groups.get_users(
                wazo_all_users_group['uuid']
            )['items']
            assert_that(
                wazo_all_users_group_members,
                has_item(has_entries(uuid=user['uuid'])),
            )

        # User created in subtenant
        with self.user(self.client, tenant_uuid=isolated['uuid'], **args) as user:
            assert_that(
                user,
                has_entries(
                    uuid=uuid_(),
                    username='foobar',
                    firstname='Alice',
                    lastname=None,
                    enabled=True,
                    tenant_uuid=isolated['uuid'],
                    emails=contains_inanyorder(
                        has_entries(
                            uuid=uuid_(),
                            address='foobar@example.com',
                            main=True,
                            confirmed=True,
                        )
                    ),
                ),
            )

            # TODO move this assertion to the user tenant tests
            tenants = self.client.users.get_tenants(user['uuid'])
            assert_that(
                tenants,
                has_entries(
                    items=contains(has_entries(uuid=isolated['uuid'])), total=1
                ),
            )

        args = {
            'uuid': 'fcf9724a-15aa-4dc5-af3c-a9acdb6a2ab9',
            'username': 'alice',
            'email_address': 'alice@example.com',
        }

        with self.user(self.client, **args) as user:
            assert_http_error(409, self.client.users.new, **args)

        assert_http_error(400, self.client.users.new, username='a' * 257)
        with self.user(self.client, username='a' * 256) as user:
            assert_that(user, has_entries(username='a' * 256))

        # User creation with no email address
        with self.user(self.client, username='bob') as user:
            assert_that(user, has_entries(username='bob', emails=empty()))

        args = {'username': 'bob', 'email_address': None}
        with self.user(self.client, **args) as user:
            assert_that(user, has_entries(emails=empty()))

        user_args = {'username': 'foobar', 'password': 'foobaz', 'enabled': False}
        with self.user(self.client, **user_args) as user:
            assert_that(user, has_entries(enabled=False))
            user_client = self.make_auth_client('foobar', 'foobaz')
            assert_http_error(401, user_client.token.new, 'wazo_user')

    def test_post_from_subtenant_user(self):
        with self.client_in_subtenant() as (client, alice, isolated):
            args = {
                'username': 'user-from-multitenant',
                'email_address': 'user-from-multitenant@example.com',
            }

            # User created in the same tenant
            with self.user(client, **args) as user:
                assert_that(user, has_entries(tenant_uuid=isolated['uuid']))

            # User created in a tenant that is not authorized
            assert_http_error(
                401, client.users.new, tenant_uuid=self.top_tenant_uuid, **args
            )

            with self.client_in_subtenant(parent_uuid=isolated['uuid']) as (
                _,
                __,
                subtenant,
            ):
                user = client.users.new(username='foo', tenant_uuid=subtenant['uuid'])
                assert_that(user, has_entries(tenant_uuid=subtenant['uuid']))

    def test_post_does_not_log_password(self):
        args = {
            'username': 'foobar',
            'firstname': 'Denver',
            'email_address': 'foobar@example.com',
            'password': 's3cr37',
        }

        time_start = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        with self.user(self.client, **args):
            pass
        logs = self.service_logs('auth', since=time_start)
        assert_that(logs, not_(contains_string(args['password'])))

    @fixtures.http.user(username='user1@example.com')
    @fixtures.http.user(email_address='user2@example.com')
    def test_post_with_same_login(self, *_):
        assert_http_error(409, self.client.users.new, username='user1@example.com')
        assert_http_error(409, self.client.users.new, username='user2@example.com')

        assert_http_error(409, self.client.users.new, email_address='user1@example.com')
        assert_http_error(409, self.client.users.new, email_address='user2@example.com')

    @fixtures.http.user(
        username='foobar', firstname='foo', lastname='bar', purpose='user'
    )
    def test_put(self, user):
        user_uuid = user['uuid']
        body = {
            'username': 'foobaz',
            'firstname': 'baz',
            'purpose': 'external_api',
            'enabled': False,
        }

        assert_http_error(404, self.client.users.edit, UNKNOWN_UUID, **body)
        with self.client_in_subtenant() as (client, bob, isolated):
            assert_http_error(404, client.users.edit, user['uuid'], **body)
            assert_http_error(
                401,
                client.users.edit,
                user['uuid'],
                tenant_uuid=self.top_tenant_uuid,
                **body,
            )
            assert_no_error(self.client.users.edit, bob['uuid'], **body)

        result = self.client.users.edit(user_uuid, **body)
        assert_that(
            result,
            has_entries(
                uuid=user_uuid,
                username='foobaz',
                firstname='baz',
                lastname=None,
                purpose='external_api',
                enabled=False,
            ),
        )

        body = {'username': 'foobaz', 'firstname': None, 'lastname': None}
        result = self.client.users.edit(user_uuid, **body)
        assert_that(result, has_entries(**body))

    def test_register_post(self):
        args = {
            'username': 'foobar',
            'lastname': 'Denver',
            'email_address': 'foobar@example.com',
            'password': 's3cr37',
        }

        with self.user(self.client, register=True, **args) as user:
            assert_that(
                user,
                has_entries(
                    uuid=uuid_(),
                    username='foobar',
                    firstname=None,
                    lastname='Denver',
                    enabled=True,
                    tenant_uuid=uuid_(),
                    emails=contains_inanyorder(
                        has_entries(
                            uuid=uuid_(),
                            address='foobar@example.com',
                            main=True,
                            confirmed=False,
                        )
                    ),
                ),
            )

            created_tenant = self.client.tenants.get(user['tenant_uuid'])
            assert_that(
                created_tenant,
                has_entries(
                    uuid=is_not(self.top_tenant_uuid), parent_uuid=self.top_tenant_uuid
                ),
            )

            url = self.get_last_email_url()
            url = url.replace('https', 'http')
            requests.get(url)

            updated_user = self.client.users.get(user['uuid'])
            assert_that(
                updated_user, has_entries(emails=contains(has_entries(confirmed=True)))
            )

            tenants = self.client.users.get_tenants(user['uuid'])
            assert_that(tenants, has_entries(items=contains(has_entries(uuid=uuid_()))))

    def test_register_post_does_not_log_password(self):
        args = {
            'username': 'foobar',
            'lastname': 'Denver',
            'email_address': 'foobar@example.com',
            'password': 's3cr37',
        }

        time_start = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        with self.user(self.client, register=True, **args):
            pass
        logs = self.service_logs('auth', since=time_start)
        assert_that(logs, not_(contains_string(args['password'])))

    def test_register_error_then_no_user_created(self):
        args = {
            'username': 'foobar',
            'lastname': 'Denver',
            'email_address': 'foobar@example.com',
            'password': 's3cr37',
        }

        self.stop_service('smtp')
        assert_that(
            calling(self.client.users.register).with_args(**args),
            raises(requests.HTTPError),
        )
        self.start_service('smtp')

        def user_registered():
            try:
                user = self.client.users.register(**args)
            except Exception as e:
                self.fail(e)

            assert_that(user, has_entries(username='foobar'))
            self.client.users.delete(user['uuid'])

        until.assert_(user_registered, timeout=3.0)

    @fixtures.http.user_register(
        username='foo', password='foobar', email_address='foo@example.com'
    )
    @fixtures.http.policy(acl=['auth.users.{{ uuid }}.password.edit'])
    def test_put_password(self, user, policy):
        self.client.users.add_policy(user['uuid'], policy['uuid'])
        new_password = 'foobaz'

        assert_http_error(
            400,
            self.client.users.change_password,
            UNKNOWN_UUID,
            new_password=new_password,
        )
        assert_http_error(
            404,
            self.client.users.change_password,
            UNKNOWN_UUID,
            old_password='wrong',
            new_password=new_password,
        )
        assert_http_error(
            401,
            self.client.users.change_password,
            user['uuid'],
            old_password='wrong',
            new_password=new_password,
        )
        assert_no_error(
            self.client.users.change_password,
            user['uuid'],
            old_password='foobar',
            new_password=new_password,
        )

        user_client = self.make_auth_client('foo', new_password)
        token_data = user_client.token.new('wazo_user', expiration=5)
        user_client.set_token(token_data['token'])

        assert_no_error(
            user_client.users.change_password,
            user['uuid'],
            old_password=new_password,
            new_password='secret',
        )

        user_client = self.make_auth_client('foo', 'secret')
        assert_no_error(user_client.token.new, 'wazo_user', expiration=5)

    @fixtures.http.user_register(password='secret')
    def test_put_password_does_not_log_password(self, user):
        time_start = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        old_password = 'secret'
        new_password = 'NewPass'
        self.client.users.change_password(
            user['uuid'],
            old_password=old_password,
            new_password=new_password,
        )
        logs = self.service_logs('auth', since=time_start)
        assert_that(logs, not_(contains_string(old_password)))
        assert_that(logs, not_(contains_string(new_password)))

    def test_list(self):
        def check_list_result(result, total, filtered, item_matcher, *usernames):
            items = item_matcher(
                *[
                    has_entries(username=username, enabled=True)
                    for username in usernames
                ]
            )
            expected = has_entries(total=total, filtered=filtered, items=items)
            assert_that(result, expected)

        with self.client_in_subtenant(username='foo') as (top_client, _, top):
            with self.client_in_subtenant(username='bar', parent_uuid=top['uuid']) as (
                sub_client,
                __,
                sub,
            ):
                with self.user(sub_client, username='baz'):
                    result = top_client.users.list()
                    check_list_result(result, 1, 1, contains, 'foo')

                    result = top_client.users.list(recurse=True)
                    check_list_result(
                        result, 3, 3, contains_inanyorder, 'foo', 'bar', 'baz'
                    )

                    result = sub_client.users.list()
                    check_list_result(result, 2, 2, contains_inanyorder, 'bar', 'baz')

                    result = self.client.users.list(tenant_uuid=top['uuid'])
                    check_list_result(result, 1, 1, contains_inanyorder, 'foo')

                    result = self.client.users.list(
                        recurse=True, tenant_uuid=top['uuid']
                    )
                    check_list_result(
                        result, 3, 3, contains_inanyorder, 'foo', 'bar', 'baz'
                    )

                    result = top_client.users.list(recurse=True, search='ba')
                    check_list_result(result, 3, 2, contains_inanyorder, 'bar', 'baz')

                    result = top_client.users.list(recurse=True, username='bar')
                    check_list_result(result, 3, 1, contains_inanyorder, 'bar')

                    result = top_client.users.list(
                        recurse=True, order='username', direction='desc'
                    )
                    check_list_result(result, 3, 3, contains, 'foo', 'baz', 'bar')

                    result = top_client.users.list(
                        recurse=True, order='username', direction='asc'
                    )
                    check_list_result(result, 3, 3, contains, 'bar', 'baz', 'foo')

                    result = top_client.users.list(
                        recurse=True, order='username', direction='asc', limit=1
                    )
                    check_list_result(result, 3, 3, contains, 'bar')

                    result = top_client.users.list(
                        recurse=True, order='username', direction='asc', offset=1
                    )
                    check_list_result(result, 3, 3, contains, 'baz', 'foo')

                    assert_http_error(400, top_client.users.list, limit='not a number')
                    assert_http_error(400, top_client.users.list, offset=-1)
                    assert_http_error(400, top_client.users.list, direction='up')
                    assert_http_error(400, top_client.users.list, order='lol')

    @fixtures.http.user_register(username='foo', email_address='foo@example.com')
    def test_get(self, user):
        assert_http_error(404, self.client.users.get, UNKNOWN_UUID)
        with self.client_in_subtenant() as (client, alice, isolated):
            assert_http_error(404, client.users.get, user['uuid'])
            assert_http_error(
                401, client.users.get, user['uuid'], tenant_uuid=self.top_tenant_uuid
            )
            assert_no_error(self.client.users.get, alice['uuid'])
            assert_no_error(client.users.get, alice['uuid'])

        result = self.client.users.get(user['uuid'])
        assert_that(
            result,
            has_entries(
                uuid=user['uuid'],
                username='foo',
                enabled=True,
                emails=contains_inanyorder(
                    has_entries(
                        address='foo@example.com',
                        confirmed=False,
                        main=True,
                    )
                ),
            ),
        )
