# Copyright 2015-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest.mock import MagicMock

from ..utils import load_ordered


def test_load_ordered():
    dependencies = MagicMock()
    dependencies.__getitem__.side_effect = lambda name: MagicMock()

    enabled = [
        'default_user',
        'default_internal',
        'default_external_api',
        'user_admin_status',
    ]
    manager = load_ordered(
        'wazo_auth.metadata',
        enabled,
        (dependencies,),
    )
    assert manager is not None
    assert len(manager.extensions) == 4
    assert [ext.name for ext in manager.extensions] == enabled
