# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Avencall
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

from xivo_auth import BaseAuthenticationBackend


class XiVOService(BaseAuthenticationBackend):

    def __init__(self, config):
        self.services = config.get('services', {})

    def get_consul_acls(self, login, args):
        service = self.services.get(login, {})
        acls = service.get('acls', [])
        return acls

    def get_acls(self, login, args):
        return ['agentd.#', 'dird.#']

    def get_ids(self, login, args):
        return login, login

    def verify_password(self, login, password):
        service = self.services.get(login, {})
        if service.get('service_key', None) == password:
            return True
        return False
