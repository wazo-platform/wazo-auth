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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

from flask import request
from wazo_auth import exceptions, http, schemas


class _BasePolicyRessource(http.ErrorCatchingResource):

    def __init__(self, policy_service):
        self.policy_service = policy_service


class Policies(_BasePolicyRessource):

    @http.required_acl('auth.policies.create')
    def post(self):
        body, errors = schemas.PolicySchema().load(request.get_json(force=True))
        if errors:
            for field in errors:
                raise exceptions.InvalidInputException(field)

        policy_uuid = self.policy_service.create(**body)

        return dict(uuid=policy_uuid, **body), 200

    @http.required_acl('auth.policies.read')
    def get(self):
        ListSchema = schemas.new_list_schema('name')
        list_params, errors = ListSchema().load(request.args)
        if errors:
            raise exceptions.InvalidListParamException(errors)

        policies = self.policy_service.list(**list_params)
        total = self.policy_service.count(**list_params)
        return {'items': policies, 'total': total}, 200


class Policy(_BasePolicyRessource):

    @http.required_acl('auth.policies.{policy_uuid}.read')
    def get(self, policy_uuid):
        policy = self.policy_service.get(policy_uuid)
        return policy, 200

    @http.required_acl('auth.policies.{policy_uuid}.delete')
    def delete(self, policy_uuid):
        self.policy_service.delete(policy_uuid)
        return '', 204

    @http.required_acl('auth.policies.{policy_uuid}.edit')
    def put(self, policy_uuid):
        body, errors = schemas.PolicySchema().load(request.get_json(force=True))
        if errors:
            for field in errors:
                raise exceptions.InvalidInputException(field)

        policy = self.policy_service.update(policy_uuid, **body)
        return policy, 200


class PolicyTemplate(_BasePolicyRessource):

    @http.required_acl('auth.policies.{policy_uuid}.edit')
    def delete(self, policy_uuid, template):
        self.policy_service.delete_acl_template(policy_uuid, template)
        return '', 204

    @http.required_acl('auth.policies.{policy_uuid}.edit')
    def put(self, policy_uuid, template):
        self.policy_service.add_acl_template(policy_uuid, template)
        return '', 204


class Plugin(object):

    def load(self, dependencies):
        api = dependencies['api']
        args = (dependencies['policy_service'],)

        api.add_resource(Policies, '/policies', resource_class_args=args)
        api.add_resource(Policy, '/policies/<string:policy_uuid>', resource_class_args=args)
        api.add_resource(PolicyTemplate, '/policies/<string:policy_uuid>/acl_templates/<template>',
                         resource_class_args=args)
