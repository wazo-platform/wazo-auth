# Copyright 2016-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import uuid

from hamcrest import assert_that, calling, equal_to, instance_of
from xivo_test_helpers.hamcrest.raises import raises

from .helpers import base, fixtures

SESSION_UUID_1 = str(uuid.uuid4())


@base.use_asset('database')
class TestAddressDAO(base.DAOTestCase):
    def setUp(self):
        super().setUp()
        self._null_address = self._address()

    @fixtures.db.tenant()
    def test_new_address(self, tenant_uuid):
        result = self._address_dao.new(tenant_uuid=tenant_uuid, **self._null_address)
        assert_that(result, equal_to(None))

        address = self._address(line_1='here')
        result = self._address_dao.new(tenant_uuid=tenant_uuid, **address)
        assert_that(result, instance_of(int))

    @fixtures.db.address(line_1='here')
    def test_update(self, address_id):
        updated_address = self._address(line_1='here', country='Canada')
        result = self._address_dao.update(address_id, **updated_address)
        assert_that(result, equal_to(address_id))
        assert_that(self._address_dao.get(address_id), equal_to(updated_address))

        result = self._address_dao.update(address_id, **self._null_address)
        assert_that(result, equal_to(None))
        assert_that(
            calling(self._address_dao.get).with_args(address_id), raises(Exception)
        )

    def _address(
        self,
        line_1=None,
        line_2=None,
        city=None,
        state=None,
        country=None,
        zip_code=None,
    ):
        return {
            'line_1': line_1,
            'line_2': line_2,
            'city': city,
            'state': state,
            'country': country,
            'zip_code': zip_code,
        }
