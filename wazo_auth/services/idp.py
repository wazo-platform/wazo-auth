# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth.services.helpers import BaseService


class IDPService(BaseService):
    def add_user(self, idp_type, user_uuid):
        user = self._dao.user.get(user_uuid)
        user.authentication_method = idp_type
        self._dao.user.session.flush()
        return user

    def remove_user(self, idp_type, user_uuid):
        user = self._dao.user.get(user_uuid)
        if user.authentication_method == idp_type:
            user.authentication_method = 'default'
            self._dao.user.session.flush()
        return user
