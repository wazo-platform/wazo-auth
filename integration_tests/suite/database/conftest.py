# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest
from ..helpers import base


@pytest.fixture(scope='package', autouse=True)
def setup_and_teardown_package():
    base.DBStarter.setUpClass()
    yield
    base.DBStarter.tearDownClass()
