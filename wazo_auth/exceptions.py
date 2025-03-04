# Copyright 2017-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from urllib.parse import urlencode

from unidecode import unidecode
from xivo.rest_api_helpers import APIException


class NoSuchBackendException(Exception):
    def __init__(self, backend_name):
        super().__init__(f'no such backend {backend_name}')


class InvalidUsernamePassword(Exception):
    def __init__(self, login):
        super().__init__(f'unknown username or password for login {login}')


class NoMatchingSAMLSession(Exception):
    def __init__(self, saml_session_id):
        super().__init__(f'unknown saml_session_id {saml_session_id}')


class UnauthorizedAuthenticationMethod(Exception):
    def __init__(self, authorized_authentication_method, proposed_auth_method, login):
        super().__init__(
            f'Unauthorized authentication method {proposed_auth_method} for login {login}: '
            f'should use {authorized_authentication_method}'
        )
        self.authorized_authentication_method = authorized_authentication_method
        self.proposed_auth_method = proposed_auth_method
        self.login = login


class UnknownRefreshToken(APIException):
    def __init__(self, client_id):
        details = {'client_id': client_id}
        msg = f'unknown refresh_token for client_id "{client_id}"'
        error_id = 'cannot-find-refresh-token-matching-client-id'
        super().__init__(404, msg, error_id, details, resource='tokens')


class UnknownRefreshTokenUUID(APIException):
    def __init__(self, uuid):
        details = {'uuid': uuid}
        msg = f'unknown refresh_token uuid "{uuid}"'
        error_id = 'cannot-find-refresh-token-matching-uuid'
        super().__init__(404, msg, error_id, details, resource='tokens')


class TokenServiceException(Exception):
    pass


class AuthenticationFailedException(TokenServiceException):
    code = 401
    _msg = 'Authentication Failed'

    def __str__(self):
        return self._msg


class ExternalAuthAlreadyExists(APIException):
    def __init__(self, auth_type):
        msg = f'This external authentication method has already been set: "{auth_type}"'
        details = {'type': auth_type}
        super().__init__(409, msg, 'conflict', details, auth_type)


class ExternalAuthConfigAlreadyExists(APIException):
    def __init__(self, auth_type):
        msg = f'This external authentication config has already been set: "{auth_type}"'
        details = {'type': auth_type}
        super().__init__(409, msg, 'conflict', details, auth_type)


class ExternalAuthConfigNotFound(APIException):
    def __init__(self, auth_type):
        msg = f'Configuration for this external auth type "{auth_type}" is not defined.'
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
        msg = f'No such address: "{address_id}"'
        details = {'id': address_id}
        super().__init__(404, msg, 'unknown-address', details, 'addresses')


class UnknownExternalAuthException(APIException):
    def __init__(self, auth_type):
        msg = f'No such external auth: "{auth_type}"'
        details = {'type': str(auth_type)}
        super().__init__(404, msg, 'unknown-external-auth', details, auth_type)


class UnknownExternalAuthConfigException(APIException):
    def __init__(self, auth_type):
        msg = f'No config found for this external auth type: "{auth_type}"'
        details = {'type': str(auth_type)}
        super().__init__(404, msg, 'unknown-external-auth', details, auth_type)


class UnknownIDPType(APIException):
    def __init__(self, idp_type):
        msg = f'No such IDP type: "{idp_type}"'
        details = {'idp_type': idp_type}
        super().__init__(404, msg, 'unknown-idp-type', details, 'idp')


class DuplicatedLDAPConfigException(Exception):
    def __init__(self, tenant_uuid):
        self.tenant_uuid = tenant_uuid
        super().__init__(
            f'Duplicated LDAP config for tenant_uuid {tenant_uuid}',
        )


class UnknownLDAPConfigException(APIException):
    def __init__(self, tenant_uuid):
        msg = f'No LDAP config found for this tenant: "{tenant_uuid}"'
        details = {'uuid': str(tenant_uuid)}
        super().__init__(404, msg, 'unknown-ldap-config', details, 'ldap_config')


class UnknownExternalAuthTypeException(APIException):
    def __init__(self, auth_type):
        msg = f'No such auth type: "{auth_type}"'
        details = {'type': str(auth_type)}
        super().__init__(404, msg, 'unknown-external-auth-type', details, 'external')


class UnknownGroupException(APIException):
    def __init__(self, group_uuid):
        msg = f'No such group: "{group_uuid}"'
        details = {'uuid': str(group_uuid)}
        super().__init__(404, msg, 'unknown-group', details, 'groups')


class SystemGroupForbidden(APIException):
    def __init__(self, group_uuid):
        msg = f'Forbidden group modification: "{group_uuid}"'
        details = {'uuid': str(group_uuid)}
        super().__init__(403, msg, 'forbidden-group', details, 'groups')


class UnknownTenantException(APIException):
    def __init__(self, tenant_uuid):
        msg = f'No such tenant: "{tenant_uuid}"'
        details = {'uuid': str(tenant_uuid)}
        super().__init__(404, msg, 'unknown-tenant', details, 'tenants')


class UnauthorizedTenantwithChildrenDelete(APIException):
    def __init__(self, tenant_uuid):
        msg = (
            f'Unauthorized delete of tenant : "{tenant_uuid}" ; '  # noqa: E702
            'since it has at least one child'
        )
        details = {'uuid': str(tenant_uuid)}
        super().__init__(400, msg, details, 'tenants')


class UnknownEmailException(APIException):
    def __init__(self, email_uuid):
        msg = f'No such email: "{email_uuid}"'
        details = {'uuid': str(email_uuid)}
        super().__init__(404, msg, 'unknown-email', details, 'emails')


class UnknownUserException(APIException):
    def __init__(self, identifier, details=None):
        msg = f'No such user: "{identifier}"'
        details = details or {'uuid': str(identifier)}
        super().__init__(404, msg, 'unknown-user', details, 'users')


class UsernameLoginAlreadyExists(APIException):
    def __init__(self, username):
        msg = f'The login "{username}" is already used'
        details = {'username': {'constraint_id': 'unique', 'message': msg}}
        super().__init__(409, 'Conflict detected', 'conflict', details, 'users')


class EmailLoginAlreadyExists(APIException):
    def __init__(self, email):
        msg = f'The login "{email}" is already used'
        details = {'email_address': {'constraint_id': 'unique', 'message': msg}}
        super().__init__(409, 'Conflict detected', 'conflict', details, 'users')


class UnknownUserUUIDException(Exception):
    def __init__(self, user_uuid):
        msg = f'No such user: "{user_uuid}"'
        super().__init__(msg)


class UnknownLoginException(Exception):
    def __init__(self, login):
        msg = f'No such user: "{login}"'
        super().__init__(msg)


class PasswordIsManagedExternallyException(APIException):
    def __init__(self, user_uuid, details=None):
        msg = f'Unable to update externally managed password for user : "{user_uuid}"'
        details = details or {'uuid': str(user_uuid)}
        super().__init__(405, msg, 'password-managed-externally', details, 'users')


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

                if 'message' in info:
                    return cls(info['message'], {field: info})

                for sub_field, sub_infos in info.items():
                    if not isinstance(sub_infos, list):
                        sub_infos = [sub_infos]
                    for sub_info in sub_infos:
                        info = {sub_field: sub_info}
                        return cls(sub_info['message'], {field: info})


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


class SAMLParamException(_BaseParamException):
    resource = 'saml'


class InvalidInputException(TokenServiceException):
    code = 400

    def __init__(self, field):
        super().__init__()
        self._field = field

    def __str__(self):
        return f'Invalid value supplied for field: {self._field}'


class InvalidLimitException(TokenServiceException):
    code = 400

    def __init__(self, limit):
        super().__init__()
        self._limit = limit

    def __str__(self):
        return f'Invalid limit: {self._limit}'


class InvalidOffsetException(TokenServiceException):
    code = 400

    def __init__(self, offset):
        super().__init__()
        self._offset = offset

    def __str__(self):
        return f'Invalid offset: {self._offset}'


class InvalidSortColumnException(TokenServiceException):
    code = 400

    def __init__(self, field):
        super().__init__()
        self._field = field

    def __str__(self):
        return f'Invalid sort column: {self._field}'


class InvalidSortDirectionException(TokenServiceException):
    code = 400

    def __init__(self, direction):
        super().__init__()
        self._direction = direction

    def __str__(self):
        return f'Invalid sort direction: {self._direction}'


class ConflictException(APIException):
    def __init__(self, resource, column, username):
        msg = f'The {column} "{username}" is already used'
        details = {column: {'constraint_id': 'unique', 'message': msg}}
        super().__init__(409, 'Conflict detected', 'conflict', details, resource)


class MasterTenantConflictException(APIException):
    def __init__(self):
        msg = 'A master tenant already exist'
        details = {'parent_uuid': {'constraint_id': 'unique', 'msg': msg}}
        super().__init__(403, 'Conflict detected', 'conflict', details, 'tenants')


class DuplicatePolicyException(TokenServiceException):
    code = 409

    def __init__(self, name):
        super().__init__()
        self._name = name

    def __str__(self):
        return f'Policy "{self._name}" already exists'


class DuplicatedRefreshTokenException(Exception):
    def __init__(self, user_uuid, client_id):
        self.client_id = client_id
        self.user_uuid = user_uuid
        msg = f'Duplicated Refresh Token for user_uuid {user_uuid} and client_id {client_id}'
        super().__init__(msg)


class DuplicateAccessException(TokenServiceException):
    code = 409

    def __init__(self, access):
        super().__init__()
        self._access = access

    def __str__(self):
        return f'Policy already associated to {self._access}'


class MaxConcurrentSessionsReached(TokenServiceException):
    code = 429

    def __init__(self, user_uuid):
        super().__init__()
        self._user_uuid = user_uuid

    def __str__(self):
        return (
            f'User {self._user_uuid} has exceeded the maximum number of active sessions'
        )


class UnknownPolicyException(TokenServiceException):
    code = 404

    def __init__(self, policy_uuid):
        self._policy_uuid = policy_uuid

    def __str__(self):
        return f'No such policy {self._policy_uuid}'


class ReadOnlyPolicyException(TokenServiceException):
    code = 403

    def __init__(self, policy_uuid):
        self._policy_uuid = policy_uuid

    def __str__(self):
        return f'Forbidden policy deletion: "{self._policy_uuid}"'


class UnknownTokenException(TokenServiceException):
    code = 404

    def __str__(self):
        return 'No such token'


class MissingAccessTokenException(TokenServiceException):
    code = 403

    def __init__(self, required_access):
        super().__init__()
        self._required_access = required_access

    def __str__(self):
        access = unidecode(self._required_access)
        return f'Unauthorized for {access}'


class MissingTenantTokenException(TokenServiceException):
    code = 403

    def __init__(self, tenant_uuid):
        super().__init__()
        self._tenant_uuid = tenant_uuid

    def __str__(self):
        return f'Unauthorized for tenant {self._tenant_uuid}'


class TopTenantNotInitialized(APIException):
    def __init__(self):
        msg = 'wazo-auth top tenant is not initialized'
        super().__init__(503, msg, 'top-tenant-not-initialized')


class DomainAlreadyExistException(APIException):
    def __init__(self, domain_name):
        msg = f'Domain name : "{domain_name}" is already in use, no duplicates allowed'
        details = {'domain_names': {'constraint-id': 'unique', 'message': msg}}
        error_id = 'conflict'
        resource = 'tenants'
        super().__init__(409, 'Conflict detected', error_id, details, resource)


class DuplicateGroupException(TokenServiceException):
    code = 409

    def __init__(self, name):
        super().__init__()
        self._name = name

    def __str__(self):
        return f'Group "{self._name}" already exists'


class UnauthorizedResourcesMutualAccessAttemptException(APIException):
    def __init__(self, user_tenant_uuid, group_tenant_uuid):
        error_code = 400
        error_id = 'missmatching-tenant'
        error_msg = 'Ressources are not in the same tenant'
        error_details = {
            'user_tenant_uuid': user_tenant_uuid,
            'group_tenant_uuid': group_tenant_uuid,
        }
        resource = 'groups'
        super().__init__(error_code, error_msg, error_id, error_details, resource)


class SAMLException(APIException):
    resource = 'saml'


class SAMLConfigurationError(SAMLException):
    def __init__(self, domain, message=None):
        error_code = 500
        error_id = 'configuration-error'
        error_msg = message or 'SAML client for domain not found or failed'
        error_details = {
            'domain': domain,
        }
        super().__init__(error_code, error_msg, error_id, error_details, self.resource)


class SAMLProcessingError(SAMLException):
    def __init__(self, error, code=500):
        error_code = code
        error_id = 'processing-error'
        error_msg = 'SAML processing failed'
        error_details = {
            'error': error,
        }
        super().__init__(error_code, error_msg, error_id, error_details, self.resource)


class SAMLProcessingErrorWithReturnURL(SAMLException):
    def __init__(self, error: str, return_url: str, code: int = 500):
        error_code = code
        error_id = 'processing-error'
        error_msg = 'SAML processing failed'
        error_details = {
            'error': error,
        }
        self.redirect_url: str = (
            return_url + '?' + urlencode({'login_failure_code': error_code})
        )
        super().__init__(error_code, error_msg, error_id, error_details, self.resource)


class SAMLConfigParameterException(APIException):
    def __init__(self, tenant_uuid, msg, code):
        details = {'uuid': str(tenant_uuid)}
        super().__init__(code, msg, 'unknown-saml-config', details, 'saml_config')


class UnknownSAMLConfigException(APIException):
    def __init__(self, tenant_uuid):
        msg = f'No SAML IDP config found for this tenant: "{tenant_uuid}"'
        details = {'uuid': str(tenant_uuid)}
        super().__init__(404, msg, 'unknown-saml-config', details, 'saml_config')


class DuplicatedSAMLConfigException(APIException):
    def __init__(self, tenant_uuid):
        msg = 'Duplicated SAML config exists'
        details = {'tenant_uuid': {'constraint_id': 'unique', 'message': msg}}
        super().__init__(409, 'Conflict detected', 'conflict', details, 'saml_config')


class UnknownSAMLSessionException(Exception):
    def __init__(self, request_id):
        super().__init__(f'no such session {request_id}')


class DuplicatedSAMLSessionException(Exception):
    def __init__(self, message):
        super().__init__(message)


class SAMLSessionSQLException(Exception):
    def __init__(self, request_id):
        super().__init__(f'e {request_id}')
