# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth.services.helpers import BaseService


class IDPService(BaseService):
    def add_user(self, idp_type, user_uuid):
        return self._dao.user.update(user_uuid, authentication_method=idp_type)

    def remove_user(self, idp_type, user_uuid):
        user = self._dao.user.get(user_uuid)
        if user.authentication_method == idp_type:
            return self.add_user('default', user_uuid)
        return user
