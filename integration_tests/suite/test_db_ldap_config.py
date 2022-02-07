# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import (
    assert_that,
    calling,
    has_entries,
    raises,
)
from wazo_auth import exceptions
from .helpers import fixtures, base
from .helpers.constants import UNKNOWN_UUID


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
