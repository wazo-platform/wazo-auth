# -*- coding: utf-8 -*-
#
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>

from .exceptions import InvalidInputException


class Manager(object):

    def __init__(self, storage):
        self._storage = storage

    def create(self, body):
        name = body.get('name')
        description = body.get('description', '')
        acl_templates = body.get('acl_templates', [])

        self._validate_name(name)
        self._validate_description(description)
        self._validate_acl_templates(acl_templates)

        uuid = self._storage.create_policy(name, description, acl_templates)

        return {'uuid': uuid,
                'name': name,
                'description': description,
                'acl_templates': acl_templates}

    def _validate_name(self, name):
        if not name or not self._is_str(name):
            raise InvalidInputException('name')

    def _validate_description(self, description):
        if not self._is_str(description):
            raise InvalidInputException('description')

    def _validate_acl_templates(self, acls):
        if not self._is_list_of_str(acls):
            raise InvalidInputException('acls')

    @staticmethod
    def _is_str(s):
        return isinstance(s, (str, unicode))

    @staticmethod
    def _is_list_of_str(l):
        if not isinstance(l, list):
            return False

        for i in l:
            if not isinstance(i, (str, unicode)):
                return False

        return True
