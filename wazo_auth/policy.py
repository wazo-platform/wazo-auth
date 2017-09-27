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

from marshmallow import fields, pre_load, Schema, validate

from .exceptions import InvalidInputException


class _PolicySchema(Schema):
    name = fields.String(validate=validate.Length(min=1, max=80), required=True)
    description = fields.String(allow_none=True, missing=None)
    acl_templates = fields.List(fields.String(), missing=[])

    @pre_load
    def warn_on_none(self, data):
        return data or {}


class Manager(object):

    def __init__(self, storage):
        self._storage = storage

    def add_acl_template(self, policy_uuid, acl_template):
        return self._storage.add_policy_acl_template(policy_uuid, acl_template)

    def create(self, body):
        name, description, acl_templates = self._extract_body(body)

        uuid = self._storage.create_policy(name, description, acl_templates)

        return {'uuid': uuid,
                'name': name,
                'description': description,
                'acl_templates': acl_templates}

    def count(self, term):
        return self._storage.count_policies(term)

    def delete(self, policy_uuid):
        return self._storage.delete_policy(policy_uuid)

    def delete_acl_template(self, policy_uuid, acl_template):
        return self._storage.delete_policy_acl_template(policy_uuid, acl_template)

    def get(self, policy_uuid):
        return self._storage.get_policy(policy_uuid)

    def list(self, term, order, direction, limit, offset):
        return self._storage.list_policies(term, order, direction, limit, offset)

    def update(self, policy_uuid, body):
        name, description, acl_templates = self._extract_body(body)

        self._storage.update_policy(policy_uuid, name, description, acl_templates)

        return {
            'uuid': policy_uuid,
            'name': name,
            'description': description,
            'acl_templates': acl_templates,
        }

    def _extract_body(self, body):
        body, errors = _PolicySchema().load(body)
        if errors:
            for field in errors:
                raise InvalidInputException(field)

        return body['name'], body['description'], body['acl_templates']
