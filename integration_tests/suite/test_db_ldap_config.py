# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import (
    assert_that,
    calling,
    has_entries,
    not_,
    raises,
)
from wazo_auth import exceptions
from .helpers import fixtures, base
from .helpers.constants import UNKNOWN_TENANT, UNKNOWN_UUID


@base.use_asset('database')
class TestLDAPConfigDAO(base.DAOTestCase):
    @fixtures.db.ldap_config()
    def test_get(self, tenant_uuid):
        ldap_config = self._ldap_config_dao.get(tenant_uuid)
        assert_that(ldap_config, has_entries(tenant_uuid=tenant_uuid))

        assert_that(
            calling(self._ldap_config_dao.get).with_args(UNKNOWN_UUID),
            raises(exceptions.UnknownLDAPConfigException),
        )

    def test_create(self):
        args = {
            'tenant_uuid': self.top_tenant_uuid,
            'host': 'localhost',
            'port': 386,
            'user_base_dn': 'ou=people,dc=wazo-platform,dc=org',
            'user_login_attribute': 'uid',
            'user_email_attribute': 'mail',
            'protocol_version': 2,
            'protocol_security': 'ldaps',
            'search_filters': '{user_login_attribute}={username}',
        }

        ldap_config_tenant = self._ldap_config_dao.create(**args)
        ldap_config = self._ldap_config_dao.get(ldap_config_tenant)
        assert_that(ldap_config, has_entries(**args))

        assert_that(
            calling(self._ldap_config_dao.create).with_args(**args),
            raises(exceptions.DuplicatedLDAPConfigException),
        )

    @fixtures.db.ldap_config()
    def test_update(self, tenant_uuid):
        args = {
            'host': 'wazo-test',
            'port': 689,
            'user_base_dn': 'ou=quebec,ou=people,dc=wazo-platform,dc=org',
            'user_login_attribute': 'cn',
            'user_email_attribute': 'udsCanonicalAddress',
            'protocol_version': 3,
            'protocol_security': 'ldaps',
            'search_filters': '{user_login_attribute}={username}',
        }
        self._ldap_config_dao.update(tenant_uuid, **args)
        ldap_config = self._ldap_config_dao.get(tenant_uuid)
        assert_that(ldap_config, has_entries(**args))

        assert_that(
            calling(self._ldap_config_dao.update).with_args(UNKNOWN_TENANT),
            raises(exceptions.UnknownLDAPConfigException),
        )

    @fixtures.db.ldap_config()
    def test_delete(self, tenant_uuid):
        assert_that(
            calling(self._ldap_config_dao.delete).with_args(UNKNOWN_TENANT),
            not_(raises(Exception)),
        )
        assert_that(
            calling(self._ldap_config_dao.delete).with_args(tenant_uuid),
            not_(raises(Exception)),
        )
        assert_that(
            calling(self._ldap_config_dao.get).with_args(tenant_uuid),
            raises(exceptions.UnknownLDAPConfigException),
        )

    @fixtures.db.ldap_config()
    def test_exists(self, tenant_uuid):
        assert_that(self._ldap_config_dao.exists(tenant_uuid))
        assert_that(not_(self._ldap_config_dao.exists(UNKNOWN_TENANT)))
