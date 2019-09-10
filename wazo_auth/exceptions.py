# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unidecode import unidecode
from xivo.rest_api_helpers import APIException


class NoSuchBackendException(Exception):

    def __init__(self, backend_name):
        super().__init__(f'no such backend {backend_name}')


class InvalidUsernamePassword(Exception):

    def __init__(self, login):
        super().__init__(f'unknown username or password for login {login}')


class UnknownRefreshToken(Exception):

    def __init__(self, refresh_token, client_id):
        super().__init__(f'unknown refresh_token "{refresh_token}" with client_id "{client_id}"')


class TokenServiceException(Exception):
    pass


class AuthenticationFailedException(TokenServiceException):

    code = 401
    _msg = 'Authentication Failed'

    def __str__(self):
        return self._msg


class ExternalAuthAlreadyExists(APIException):

    def __init__(self, auth_type):
        msg = 'This external authentification method has already been set: "{}"'.format(auth_type)
        details = {'type': auth_type}
        super().__init__(409, msg, 'conflict', details, auth_type)


class ExternalAuthConfigAlreadyExists(APIException):

    def __init__(self, auth_type):
        msg = 'This external authentification config has already been set: "{}"'.format(auth_type)
        details = {'type': auth_type}
        super().__init__(409, msg, 'conflict', details, auth_type)


class ExternalAuthConfigNotFound(APIException):

    def __init__(self, auth_type):
        msg = 'Configuration for this external auth type "{}" is not defined.'.format(auth_type)
        details = {'type': auth_type}
        super().__init__(404, msg, 'unknown-config', details, auth_type)


class InvalidListParamException(APIException):

    def __init__(self, message, details=None):
        super().__init__(400, message, 'invalid-list-param', details, 'users')

    @classmethod
    def from_errors(cls, errors):
        for field, infos in errors.items():
            if not isinstance(infos, list):
                infos = [infos]
            for info in infos:
                return cls(info['message'], {field: info})


class UnknownAddressException(APIException):

    def __init__(self, address_id):
        msg = 'No such address: "{}"'.format(address_id)
        details = {'id': address_id}
        super().__init__(404, msg, 'unknown-address', details, 'addresses')


class UnknownExternalAuthException(APIException):

    def __init__(self, auth_type):
        msg = 'No such external auth: "{}"'.format(auth_type)
        details = {'type': str(auth_type)}
        super().__init__(
            404, msg, 'unknown-external-auth', details, auth_type)


class UnknownExternalAuthConfigException(APIException):

    def __init__(self, auth_type):
        msg = 'No config found for this external auth type: "{}"'.format(auth_type)
        details = {'type': str(auth_type)}
        super().__init__(
            404, msg, 'unknown-external-auth', details, auth_type)


class UnknownExternalAuthTypeException(APIException):

    def __init__(self, auth_type):
        msg = 'No such auth type: "{}"'.format(auth_type)
        details = {'type': str(auth_type)}
        super().__init__(
            404, msg, 'unknown-external-auth-type', details, 'external')


class UnknownGroupException(APIException):

    def __init__(self, group_uuid):
        msg = 'No such group: "{}"'.format(group_uuid)
        details = {'uuid': str(group_uuid)}
        super().__init__(404, msg, 'unknown-group', details, 'groups')


class UnknownTenantException(APIException):

    def __init__(self, tenant_uuid):
        msg = 'No such tenant: "{}"'.format(tenant_uuid)
        details = {'uuid': str(tenant_uuid)}
        super().__init__(404, msg, 'unknown-tenant', details, 'tenants')


class UnknownEmailException(APIException):

    def __init__(self, email_uuid):
        msg = 'No such email: "{}"'.format(email_uuid)
        details = {'uuid': str(email_uuid)}
        super().__init__(404, msg, 'unknown-email', details, 'emails')


class UnknownUserException(APIException):

    def __init__(self, identifier, details=None):
        msg = 'No such user: "{}"'.format(identifier)
        details = details or {'uuid': str(identifier)}
        super().__init__(404, msg, 'unknown-user', details, 'users')


class UnknownUsernameException(Exception):

    def __init__(self, username):
        msg = 'No such user: "{}"'.format(username)
        super().__init__(msg)


class _BaseParamException(APIException):

    def __init__(self, message, details=None):
        super().__init__(400, message, 'invalid-data', details, self.resource)

    @classmethod
    def from_errors(cls, errors):
        for field, infos in errors.items():
            if not isinstance(infos, list):
                infos = [infos]
            for info in infos:
                if isinstance(info, (str, bytes)):
                    info = {'message': info}
                return cls(info['message'], {field: info})



class GroupParamException(_BaseParamException):

    resource = 'groups'


class InitParamException(_BaseParamException):

    resource = 'init'


class TenantParamException(_BaseParamException):

    resource = 'tenants'


class PasswordChangeException(_BaseParamException):

    resource = 'users'


class UserParamException(_BaseParamException):

    resource = 'users'


class EmailUpdateException(_BaseParamException):

    resource = 'emails'


class InvalidInputException(TokenServiceException):

    code = 400

    def __init__(self, field):
        super().__init__()
        self._field = field

    def __str__(self):
        return 'Invalid value supplied for field: {}'.format(self._field)


class InvalidLimitException(TokenServiceException):

    code = 400

    def __init__(self, limit):
        super().__init__()
        self._limit = limit

    def __str__(self):
        return 'Invalid limit: {}'.format(self._limit)


class InvalidOffsetException(TokenServiceException):

    code = 400

    def __init__(self, offset):
        super().__init__()
        self._offset = offset

    def __str__(self):
        return 'Invalid offset: {}'.format(self._offset)


class InvalidSortColumnException(TokenServiceException):

    code = 400

    def __init__(self, field):
        super().__init__()
        self._field = field

    def __str__(self):
        return 'Invalid sort column: {}'.format(self._field)


class InvalidSortDirectionException(TokenServiceException):

    code = 400

    def __init__(self, direction):
        super().__init__()
        self._direction = direction

    def __str__(self):
        return 'Invalid sort direction: {}'.format(self._direction)


class ConflictException(APIException):

    def __init__(self, resource, column, username):
        msg = 'The {} "{}" is already used'.format(column, username)
        details = {column: {'constraint_id': 'unique', 'message': msg}}
        super().__init__(409, 'Conflict detected', 'conflict', details, resource)


class MasterTenantConflictException(APIException):

    def __init__(self):
        msg = 'A master tenant already exist'
        details = {'parent_uuid': {'constraint_id': 'unique', 'msg': msg}}
        super().__init__(
            403, 'Conflict detected', 'conflict', details, 'tenants')


class DuplicatePolicyException(TokenServiceException):

    code = 409

    def __init__(self, name):
        super().__init__()
        self._name = name

    def __str__(self):
        return 'Policy "{}" already exists'.format(self._name)


class DuplicateTemplateException(TokenServiceException):

    code = 409

    def __init__(self, template):
        super().__init__()
        self._template = template

    def __str__(self):
        return 'Policy already associated to {}'.format(self._template)


class UnknownPolicyException(TokenServiceException):

    code = 404

    def __init__(self, policy_uuid):
        self._policy_uuid = policy_uuid

    def __str__(self):
        return 'No such policy {}'.format(self._policy_uuid)


class UnknownTokenException(TokenServiceException):

    code = 404

    def __str__(self):
        return 'No such token'


class MissingACLTokenException(TokenServiceException):

    code = 403

    def __init__(self, required_acl):
        super().__init__()
        self._required_acl = required_acl

    def __str__(self):
        return 'Unauthorized for {}'.format(unidecode(self._required_acl))


class MissingTenantTokenException(TokenServiceException):

    code = 403

    def __init__(self, tenant_uuid):
        super().__init__()
        self._tenant_uuid = tenant_uuid

    def __str__(self):
        return 'Unauthorized for tenant {}'.format(self._tenant_uuid)
