# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from hamcrest import (
    assert_that,
    is_not,
    none,
)
from .helpers import base


def setup_module():
    base.DBStarter.setUpClass()


def teardown_module():
    base.DBStarter.tearDownClass()


class TestSessionDAO(base.DAOTestCase):

    def test_create(self):
        tenant_uuid = self._session_dao.create()
        assert_that(tenant_uuid, is_not(none()))
