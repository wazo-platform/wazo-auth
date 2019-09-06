# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth import exceptions

from .base import BaseDAO


class RefreshTokenDAO(BaseDAO):

    def get(self, refresh_token, client_id):
        raise exceptions.UnknownRefreshToken(refresh_token, client_id)
