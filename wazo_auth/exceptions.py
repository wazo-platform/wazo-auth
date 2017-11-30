# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from unidecode import unidecode
from xivo.rest_api_helpers import APIException


class ManagerException(Exception):
    pass


class AuthenticationFailedException(ManagerException):

    code = 401
    _msg = 'Authentication Failed'

    def __str__(self):
        return self._msg


class ExternalAuthAlreadyExists(APIException):

    def __init__(self, auth_type):
        msg = 'This external authentification method has already been set: "{}"'.format(auth_type)
        details = dict(type=auth_type)
        super(ExternalAuthAlreadyExists, self).__init__(409, msg, 'conflict', details, auth_type)


class InvalidListParamException(APIException):

    def __init__(self, message, details=None):
        super(InvalidListParamException, self).__init__(400, message, 'invalid_list_param', details, 'users')

    @classmethod
    def from_errors(cls, errors):
        for field, infos in errors.iteritems():
            if not isinstance(infos, list):
                infos = [infos]
            for info in infos:
                return cls(info['message'], {field: info})


class UnknownExternalAuthException(APIException):

    def __init__(self, auth_type):
        msg = 'No such external auth: "{}"'.format(auth_type)
        details = dict(type=str(auth_type))
        super(UnknownExternalAuthException, self).__init__(
            404, msg, 'unknown_external_auth', details, auth_type)


class UnknownExternalAuthTypeException(APIException):

    def __init__(self, auth_type):
        msg = 'No such auth type: "{}"'.format(auth_type)
        details = dict(type=str(auth_type))
        super(UnknownExternalAuthTypeException, self).__init__(
            404, msg, 'unknown_external_auth_type', details, 'external')


class UnknownGroupException(APIException):

    def __init__(self, group_uuid):
        msg = 'No such group: "{}"'.format(group_uuid)
        details = dict(uuid=str(group_uuid))
        super(UnknownGroupException, self).__init__(404, msg, 'unknown_group', details, 'groups')


class UnknownTenantException(APIException):

    def __init__(self, tenant_uuid):
        msg = 'No such tenant: "{}"'.format(tenant_uuid)
        details = dict(uuid=str(tenant_uuid))
        super(UnknownTenantException, self).__init__(404, msg, 'unknown_tenant', details, 'tenants')


class UnknownUserException(APIException):

    def __init__(self, user_uuid):
        msg = 'No such user: "{}"'.format(user_uuid)
        details = dict(uuid=str(user_uuid))
        super(UnknownUserException, self).__init__(404, msg, 'unknown_user', details, 'users')


class UnknownUsernameException(Exception):

    def __init__(self, username):
        msg = 'No such user: "{}"'.format(username)
        super(UnknownUsernameException, self).__init__(msg)


class _BaseParamException(APIException):

    def __init__(self, message, details=None):
        super(_BaseParamException, self).__init__(400, message, 'invalid_data', details, self.resource)

    @classmethod
    def from_errors(cls, errors):
        for field, infos in errors.iteritems():
            if not isinstance(infos, list):
                infos = [infos]
            for info in infos:
                return cls(info['message'], {field: info})


class GroupParamException(_BaseParamException):

    resource = 'groups'


class TenantParamException(_BaseParamException):

    resource = 'tenants'


class UserParamException(_BaseParamException):

    resource = 'users'


class InvalidInputException(ManagerException):

    code = 400

    def __init__(self, field):
        super(InvalidInputException, self).__init__()
        self._field = field

    def __str__(self):
        return 'Invalid value supplied for field: {}'.format(self._field)


class InvalidLimitException(ManagerException):

    code = 400

    def __init__(self, limit):
        super(InvalidLimitException, self).__init__()
        self._limit = limit

    def __str__(self):
        return 'Invalid limit: {}'.format(self._limit)


class InvalidOffsetException(ManagerException):

    code = 400

    def __init__(self, offset):
        super(InvalidOffsetException, self).__init__()
        self._offset = offset

    def __str__(self):
        return 'Invalid offset: {}'.format(self._offset)


class InvalidSortColumnException(ManagerException):

    code = 400

    def __init__(self, field):
        super(InvalidSortColumnException, self).__init__()
        self._field = field

    def __str__(self):
        return 'Invalid sort column: {}'.format(self._field)


class InvalidSortDirectionException(ManagerException):

    code = 400

    def __init__(self, direction):
        super(InvalidSortDirectionException, self).__init__()
        self._direction = direction

    def __str__(self):
        return 'Invalid sort direction: {}'.format(self._direction)


class ConflictException(APIException):

    def __init__(self, resource, column, username):
        msg = 'The {} "{}" is already used'.format(column, username)
        details = {column: {'constraint_id': 'unique', 'message': msg}}
        super(ConflictException, self).__init__(409, 'Conflict detected', 'conflict', details, resource)


class DuplicatePolicyException(ManagerException):

    code = 409

    def __init__(self, name):
        super(DuplicatePolicyException, self).__init__()
        self._name = name

    def __str__(self):
        return 'Policy "{}" already exists'.format(self._name)


class DuplicateTemplateException(ManagerException):

    code = 409

    def __init__(self, template):
        super(DuplicateTemplateException, self).__init__()
        self._template = template

    def __str__(self):
        return 'Policy already associated to {}'.format(self._template)


class UnknownPolicyException(ManagerException):

    code = 404

    def __init__(self, policy_uuid):
        self._policy_uuid = policy_uuid

    def __str__(self):
        return 'No such policy "%s"'.format(self._policy_uuid)


class UnknownTokenException(ManagerException):

    code = 404

    def __str__(self):
        return 'No such token'


class MissingACLTokenException(ManagerException):

    code = 403

    def __init__(self, required_acl):
        super(MissingACLTokenException, self).__init__()
        self._required_acl = required_acl

    def __str__(self):
        return 'Unauthorized for {}'.format(unidecode(self._required_acl))
