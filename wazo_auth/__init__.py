# Copyright 2015-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth.interfaces import (
    DEFAULT_XIVO_UUID,
    BaseAuthenticationBackend,
    BaseEmailNotification,
    BaseMetadata,
)

__all__ = [
    'BaseAuthenticationBackend',
    'BaseEmailNotification',
    'BaseMetadata',
    'DEFAULT_XIVO_UUID',
]
