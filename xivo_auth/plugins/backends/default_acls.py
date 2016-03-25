# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Avencall
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

DEFAULT_USER_ACLS = ['confd.users.me.read',
                     'confd.users.me.update',
                     'confd.users.me.funckeys.*.*',
                     'confd.users.me.#.read',
                     'confd.users.me.services.*.*',
                     'ctid-ng.calls.create',
                     'ctid-ng.calls.*.read',
                     'ctid-ng.calls.*.delete',
                     'dird.#.me.read',
                     'dird.directories.favorites.#',
                     'dird.directories.lookup.*.headers.read',
                     'dird.directories.lookup.*.read',
                     'dird.directories.personal.*.read',
                     'dird.personal.#',
                     'events.calls.me',
                     'events.statuses.*',
                     'events.switchboards',
                     'events.users.me.services.*.*',
                     'websocketd']
