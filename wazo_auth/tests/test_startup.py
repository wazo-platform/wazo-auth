# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest.mock import Mock, patch

from .. import startup


def test_enable_external_auth_types_commits_the_write():
    dao = Mock()

    with patch('wazo_auth.database.helpers.Session') as Session:
        startup.enable_external_auth_types(dao, ['google', 'mobile'])

    dao.external_auth.enable_all.assert_called_once_with(['google', 'mobile'])
    Session.commit.assert_called_once_with()
