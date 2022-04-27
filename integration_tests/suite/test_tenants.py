# Copyright 2015-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from functools import partial
from hamcrest import (
    assert_that,
    contains,
    contains_inanyorder,
    empty,
    equal_to,
    has_entries,
    has_item,
    has_entry,
    is_,
    is_not,
)
from sqlalchemy import and_
from wazo_auth.database import models
from wazo_auth.database.queries import tenant
from wazo_test_helpers import until
from wazo_test_helpers.hamcrest.uuid_ import uuid_
from .helpers import fixtures, base
from .helpers.base import (
    ADDRESS_NULL,
    assert_http_error,
    assert_no_error,
    assert_sorted,
    SUB_TENANT_UUID,
)
from .helpers.constants import (
    ALL_USERS_POLICY_SLUG,
    DEFAULT_POLICIES_SLUG,
    NB_DEFAULT_POLICIES,
    UNKNOWN_UUID,
)

ADDRESS_1 = {
    'line_1': 'Here',
    'city': 'Québec',
    'state': 'Québec',
    'country': 'Canada',
    'zip_code': 'H0H 0H0',
}
PHONE_1 = '555-555-5555'

VALID_DOMAIN_NAMES_1 = ['wazo.io', 'stack.dev.wazo.io']
VALID_DOMAIN_NAMES_2 = ['gmail.com', 'yahoo.com', 'google.ca']
VALID_DOMAIN_NAMES_3 = ['outlook.fr', 'mail.yahoo.fr']


@base.use_asset('base')
class TestTenants(base.APIIntegrationTest):
    @fixtures.http.tenant(
        name='foobar',
        address=ADDRESS_1,
        phone=PHONE_1,
        slug='slug1',
        domain_names=VALID_DOMAIN_NAMES_1,
    )
    @fixtures.http.tenant(
        uuid='6668ca15-6d9e-4000-b2ec-731bc7316767',
        name='foobaz',
        slug='slug2',
        domain_names=VALID_DOMAIN_NAMES_2,
    )
    @fixtures.http.tenant(slug='slug3')
    def test_post(self, foobar, foobaz, other):
        assert_that(
            other,
            has_entries(
                uuid=uuid_(),
                name=None,
                slug='slug3',
                parent_uuid=self.top_tenant_uuid,
                address=has_entries(**ADDRESS_NULL),
                domain_names=is_(empty()),
            ),
        )
        assert_that(
            foobaz,
            has_entries(
                uuid='6668ca15-6d9e-4000-b2ec-731bc7316767',
                name='foobaz',
                slug='slug2',
                parent_uuid=self.top_tenant_uuid,
                address=has_entries(**ADDRESS_NULL),
                domain_names=is_not(empty()),
            ),
        )

        assert_that(
            foobar,
            has_entries(
                uuid=uuid_(),
                name='foobar',
                slug='slug1',
                phone=PHONE_1,
                parent_uuid=self.top_tenant_uuid,
                address=has_entries(**ADDRESS_1),
                domain_names=is_not(empty()),
            ),
        )

        s = tenant.TenantDAO().session

        filter_ = and_(
            models.DomainName.tenant_uuid == foobar['uuid'],
            models.DomainName.name.in_(VALID_DOMAIN_NAMES_1),
        )
        names = s.query(models.DomainName.name).filter(filter_).all()
        names = [name[0] for name in names]
        assert_that(sorted(VALID_DOMAIN_NAMES_1), equal_to(sorted(names)))

        filter_ = and_(
            models.DomainName.tenant_uuid == foobaz['uuid'],
            models.DomainName.name.in_(VALID_DOMAIN_NAMES_2),
        )
        names = s.query(models.DomainName.name).filter(filter_).all()
        names = [name[0] for name in names]
        assert_that(sorted(VALID_DOMAIN_NAMES_2), equal_to(sorted(names)))

        wazo_all_users_groups = self.client.groups.list(
            search='wazo-all-users', recurse=True
        )['items']
        assert_that(
            wazo_all_users_groups,
            contains_inanyorder(
                has_entries(
                    name=f'wazo-all-users-tenant-{self.top_tenant_uuid}',
                    tenant_uuid=self.top_tenant_uuid,
                ),
                has_entries(
                    name=f'wazo-all-users-tenant-{foobar["uuid"]}',
                    tenant_uuid=foobar['uuid'],
                ),
                has_entries(
                    name=f'wazo-all-users-tenant-{foobaz["uuid"]}',
                    tenant_uuid=foobaz['uuid'],
                ),
                has_entries(
                    name=f'wazo-all-users-tenant-{other["uuid"]}',
                    tenant_uuid=other['uuid'],
                ),
            ),
        )

        def expected_policies(tenant_uuid):
            return contains(
                has_entries(
                    slug=ALL_USERS_POLICY_SLUG,
                    tenant_uuid=tenant_uuid,
                    acl=has_item('integration_tests.access'),
                )
            )

        # Assert default policies from admin point of view (recurse=True)
        wazo_all_users_policies = [
            {
                'group': wazo_all_users_group,
                'policies': self.client.groups.get_policies(
                    wazo_all_users_group['uuid'], recurse=True
                )['items'],
            }
            for wazo_all_users_group in wazo_all_users_groups
        ]

        assert_that(
            wazo_all_users_policies,
            contains_inanyorder(
                has_entries(
                    group=has_entries(tenant_uuid=self.top_tenant_uuid),
                    policies=expected_policies(self.top_tenant_uuid),
                ),
                has_entries(
                    group=has_entries(tenant_uuid=foobar['uuid']),
                    policies=expected_policies(self.top_tenant_uuid),
                ),
                has_entries(
                    group=has_entries(tenant_uuid=foobaz['uuid']),
                    policies=expected_policies(self.top_tenant_uuid),
                ),
                has_entries(
                    group=has_entries(tenant_uuid=other['uuid']),
                    policies=expected_policies(self.top_tenant_uuid),
                ),
            ),
        )

        # Assert default policies from tenant point of view
        result = []
        for group in wazo_all_users_groups:
            self.client.tenant_uuid = group['tenant_uuid']
            policies = self.client.groups.get_policies(group['uuid'])['items']
            self.client.tenant_uuid = None
            result.append({'group': group, 'policies': policies})

        assert_that(
            result,
            contains_inanyorder(
                has_entries(
                    group=has_entries(tenant_uuid=self.top_tenant_uuid),
                    policies=expected_policies(self.top_tenant_uuid),
                ),
                has_entries(
                    group=has_entries(tenant_uuid=foobar['uuid']),
                    policies=expected_policies(foobar['uuid']),
                ),
                has_entries(
                    group=has_entries(tenant_uuid=foobaz['uuid']),
                    policies=expected_policies(foobaz['uuid']),
                ),
                has_entries(
                    group=has_entries(tenant_uuid=other['uuid']),
                    policies=expected_policies(other['uuid']),
                ),
            ),
        )

        tenant_uuids = [
            self.top_tenant_uuid,
            foobar['uuid'],
            foobaz['uuid'],
            other['uuid'],
        ]
        slug = ALL_USERS_POLICY_SLUG
        for tenant_uuid in tenant_uuids:
            assert_that(
                self.client.tenants.get_policies(tenant_uuid)['items'],
                has_item(has_entries(slug=slug, tenant_uuid=tenant_uuid)),
            )

        params = {'name': 'subtenant', 'parent_uuid': foobar['uuid']}
        with self.tenant(self.client, **params) as subtenant:
            assert_that(subtenant, has_entries(uuid=uuid_(), **params))

    def test_tenant_created_event(self):
        routing_key = 'auth.tenants.*.created'
        msg_accumulator = self.bus.accumulator(routing_key)
        name = 'My tenant'
        slug = 'my_tenant'
        tenant = self.client.tenants.new(name=name, slug=slug)

        def bus_received_msg():
            assert_that(
                msg_accumulator.accumulate(with_headers=True),
                contains(
                    has_entries(
                        message=has_entries(
                            name='auth_tenant_added',
                            data=has_entries(name=name, slug=slug),
                        ),
                        headers=has_entry('tenant_uuid', tenant['uuid']),
                    )
                ),
            )

        try:
            until.assert_(bus_received_msg, tries=10, interval=0.25)
        finally:
            self.client.tenants.delete(tenant['uuid'])

    @fixtures.http.tenant(slug='dup')
    def test_post_duplicate_slug(self, a):
        assert_http_error(409, self.client.tenants.new, slug='dup')

    @fixtures.http.tenant(domain_names=VALID_DOMAIN_NAMES_1)
    def test_post_duplicate_domain_names(self, a):
        assert_http_error(409, self.client.tenants.new, domain_names=['wazo.io'])

    def test_post_invalid_domain_names(self):
        invalid_domain_names = [
            '-wazo.io',
            ' wazo.io' '#',
            '123',
            'wazo .io',
            'wazo.io-',
            'wazo',
            '=wazo.io',
            '+wazo.io',
            '_wazo.io',
            'wazo_io',
            'wazo_io  ',
            'x' * 62,
        ]
        for invalid_domain_name in invalid_domain_names:
            assert_http_error(
                400, self.client.tenants.new, domain_names=list(invalid_domain_name)
            )

    @fixtures.http.tenant(domain_names=VALID_DOMAIN_NAMES_2)
    def test_delete(self, tenant):
        with self.client_in_subtenant() as (client, user, sub_tenant):
            assert_http_error(404, client.tenants.delete, tenant['uuid'])
            assert_http_error(403, client.tenants.delete, sub_tenant['uuid'])

        assert_no_error(self.client.tenants.delete, tenant['uuid'])
        assert_http_error(404, self.client.tenants.delete, tenant['uuid'])

    @fixtures.http.tenant(domain_names=VALID_DOMAIN_NAMES_3)
    def test_delete_tenant_with_children(self, tenant):
        with self.client_in_subtenant(parent_uuid=tenant['uuid']) as (
            client,
            user,
            sub_tenant,
        ):
            assert_http_error(400, self.client.tenants.delete, tenant['uuid'])

    @fixtures.http.tenant(address=ADDRESS_1)
    def test_get_one(self, tenant):
        with self.client_in_subtenant() as (client, user, sub_tenant):
            assert_http_error(404, client.tenants.get, tenant['uuid'])
            result = client.tenants.get(sub_tenant['uuid'])
            assert_that(result, equal_to(sub_tenant))

        result = self.client.tenants.get(tenant['uuid'])
        assert_that(result, equal_to(tenant))

        assert_http_error(404, self.client.tenants.get, UNKNOWN_UUID)

    @fixtures.http.tenant(name='foobar', slug='aaa', domain_names=VALID_DOMAIN_NAMES_1)
    @fixtures.http.tenant(name='foobaz', slug='bbb', domain_names=VALID_DOMAIN_NAMES_2)
    @fixtures.http.tenant(
        name='foobarbaz', slug='ccc', domain_names=VALID_DOMAIN_NAMES_3
    )
    # extra tenant: "master" tenant
    def test_list(self, foobar, foobaz, foobarbaz):
        top_tenant = self.get_top_tenant()

        def then(result, total=4, filtered=4, item_matcher=contains(top_tenant)):
            assert_that(
                result, has_entries(items=item_matcher, total=total, filtered=filtered)
            )

        result = self.client.tenants.list()
        matcher = contains_inanyorder(
            has_entries(uuid=foobaz['uuid']),
            has_entries(uuid=foobar['uuid']),
            has_entries(uuid=foobarbaz['uuid']),
            has_entries(uuid=top_tenant['uuid']),
        )
        then(result, item_matcher=matcher)

        result = self.client.tenants.list(uuid=foobaz['uuid'])
        matcher = contains_inanyorder(
            has_entries(uuid=foobaz['uuid']),
        )
        then(result, filtered=1, item_matcher=matcher)

        result = self.client.tenants.list(slug='ccc')
        matcher = contains_inanyorder(
            has_entries(uuid=foobarbaz['uuid']),
        )
        then(result, filtered=1, item_matcher=matcher)

        result = self.client.tenants.list(search='bar')
        matcher = contains_inanyorder(
            has_entries(uuid=foobar['uuid']),
            has_entries(uuid=foobarbaz['uuid']),
        )
        then(result, filtered=2, item_matcher=matcher)

        result = self.client.tenants.list(domain_name='outlook.fr')
        matcher = contains_inanyorder(
            has_entries(uuid=foobarbaz['uuid']),
        )
        then(result, filtered=1, item_matcher=matcher)

        result = self.client.tenants.list(search_domain='outlook')
        matcher = contains_inanyorder(
            has_entries(uuid=foobarbaz['uuid']),
        )
        then(result, filtered=1, item_matcher=matcher)

        result = self.client.tenants.list(search='bbb')
        matcher = contains_inanyorder(
            has_entries(uuid=foobaz['uuid']),
        )
        then(result, filtered=1, item_matcher=matcher)

        result = self.client.tenants.list(limit=1, offset=1, order='name')
        matcher = contains_inanyorder(
            has_entries(uuid=foobarbaz['uuid']),
        )
        then(result, item_matcher=matcher)

        result = self.client.tenants.list(order='slug')
        matcher = contains_inanyorder(
            has_entries(uuid=foobar['uuid']),
            has_entries(uuid=foobaz['uuid']),
            has_entries(uuid=foobarbaz['uuid']),
            has_entries(slug='master'),
        )
        then(result, item_matcher=matcher)

        result = self.client.tenants.list(order='name', direction='desc')
        matcher = contains_inanyorder(
            has_entries(uuid=top_tenant['uuid']),
            has_entries(uuid=foobaz['uuid']),
            has_entries(uuid=foobarbaz['uuid']),
            has_entries(uuid=foobar['uuid']),
        )
        then(result, item_matcher=matcher)

        assert_http_error(400, self.client.tenants.list, limit='foo')
        assert_http_error(400, self.client.tenants.list, offset=-1)

        with self.client_in_subtenant() as (client, user, sub_tenant):
            with self.tenant(client, name='subsub') as subsub:
                result = client.tenants.list()
                matcher = contains_inanyorder(
                    has_entries(uuid=sub_tenant['uuid']),
                    has_entries(uuid=subsub['uuid']),
                )
                then(result, total=2, filtered=2, item_matcher=matcher)

    @fixtures.http.tenant()
    @fixtures.http.user()
    def test_put(self, tenant, user):
        name = 'foobar'
        body = {'name': name, 'address': ADDRESS_1, 'contact': user['uuid']}
        body_with_unknown_contact = dict(body)
        body_with_unknown_contact['contact'] = UNKNOWN_UUID

        with self.client_in_subtenant() as (client, _, sub_tenant):
            assert_http_error(404, client.tenants.edit, tenant['uuid'], **body)
            assert_no_error(client.tenants.edit, sub_tenant['uuid'], **body)

        assert_http_error(400, self.client.tenants.edit, tenant['uuid'], name=False)
        assert_http_error(404, self.client.tenants.edit, UNKNOWN_UUID, **body)
        assert_http_error(
            404, self.client.tenants.edit, tenant['uuid'], **body_with_unknown_contact
        )

        result = self.client.tenants.edit(tenant['uuid'], **body)

        assert_that(
            result,
            has_entries(
                uuid=tenant['uuid'],
                name=name,
                contact=user['uuid'],
                address=has_entries(**ADDRESS_1),
            ),
        )

    @fixtures.http.tenant(slug='ABC')
    def test_put_slug_is_read_only(self, tenant):
        new_body = dict(tenant)
        new_body['slug'] = 'DEF'

        result = self.client.tenants.edit(tenant['uuid'], **new_body)

        assert_that(result, has_entries(**tenant))


@base.use_asset('base')
class TestTenantPolicyAssociation(base.APIIntegrationTest):
    @fixtures.http.tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='foo', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='bar', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='baz', tenant_uuid=SUB_TENANT_UUID)
    def test_policy_list(self, _, foo, bar, baz):
        assert_http_error(404, self.client.tenants.get_policies, UNKNOWN_UUID)
        with self.client_in_subtenant(parent_uuid=SUB_TENANT_UUID) as (
            client,
            _,
            sub_tenant,
        ):
            assert_http_error(404, client.tenants.get_policies, SUB_TENANT_UUID)

        action = partial(self.client.tenants.get_policies, SUB_TENANT_UUID)

        result = action()
        expected = contains_inanyorder(
            has_entries(name='foo'),
            has_entries(name='bar'),
            has_entries(name='baz'),
            *[has_entries(name=slug) for slug in DEFAULT_POLICIES_SLUG],
        )
        assert_that(
            result,
            has_entries(
                total=3 + NB_DEFAULT_POLICIES,
                filtered=3 + NB_DEFAULT_POLICIES,
                items=expected,
            ),
        )

        result = action(search='ba')
        expected = contains_inanyorder(
            has_entries(name='bar'),
            has_entries(name='baz'),
        )
        assert_that(
            result,
            has_entries(total=3 + NB_DEFAULT_POLICIES, filtered=2, items=expected),
        )

    @fixtures.http.tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='foo', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='bar', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='baz', tenant_uuid=SUB_TENANT_UUID)
    def test_policy_list_sorting(self, _, foo, bar, baz):
        action = partial(self.client.tenants.get_policies, SUB_TENANT_UUID)

        expected = [
            has_entries(name='bar'),
            has_entries(name='baz'),
            has_entries(name='foo'),
            # default_policies
            has_entries(name='wazo-all-users-policy'),
            has_entries(name='wazo_default_admin_policy'),
            has_entries(name='wazo_default_user_policy'),
        ]
        assert_sorted(action, order='name', expected=expected)

    @fixtures.http.tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='foo', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='bar', tenant_uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(name='baz', tenant_uuid=SUB_TENANT_UUID)
    def test_list_paginating(self, _, foo, bar, baz):
        action = partial(
            self.client.tenants.get_policies,
            SUB_TENANT_UUID,
            order='name',
            direction='asc',
        )

        result = action(offset=1)
        expected = contains(
            has_entries(name='baz'),
            has_entries(name='foo'),
            # default_policies
            has_entries(name='wazo-all-users-policy'),
            has_entries(name='wazo_default_admin_policy'),
            has_entries(name='wazo_default_user_policy'),
        )
        assert_that(
            result,
            has_entries(
                total=3 + NB_DEFAULT_POLICIES,
                filtered=3 + NB_DEFAULT_POLICIES,
                items=expected,
            ),
        )

        result = action(limit=2)
        expected = contains(
            has_entries(name='bar'),
            has_entries(name='baz'),
        )
        assert_that(
            result,
            has_entries(
                total=3 + NB_DEFAULT_POLICIES,
                filtered=3 + NB_DEFAULT_POLICIES,
                items=expected,
            ),
        )

    @fixtures.http.tenant(uuid=SUB_TENANT_UUID)
    @fixtures.http.policy(slug='top_shared', shared=True)
    @fixtures.http.policy(slug='child', tenant_uuid=SUB_TENANT_UUID)
    def test_policy_list_with_shared(self, *args):
        result = self.client.tenants.get_policies(SUB_TENANT_UUID)
        assert_that(
            result,
            has_entries(
                total=2 + NB_DEFAULT_POLICIES,
                filtered=2 + NB_DEFAULT_POLICIES,
                items=contains_inanyorder(
                    has_entries(slug='top_shared'),
                    has_entries(slug='child'),
                    *[has_entries(name=slug) for slug in DEFAULT_POLICIES_SLUG],
                ),
            ),
        )
