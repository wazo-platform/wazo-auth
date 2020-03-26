# Copyright 2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo_test_helpers import until

from .helpers.base import WazoAuthTestCase


class TestStatusAllOK(WazoAuthTestCase):

    asset = 'base'

    def test_head_status_ok(self):
        def status_ok():
            self.client.status.check()

        until.assert_(status_ok, timeout=5)
