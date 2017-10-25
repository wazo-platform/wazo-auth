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

from unidecode import unidecode
from xivo.rest_api_helpers import APIException


class ManagerException(Exception):
    pass


class AuthenticationFailedException(ManagerException):

    code = 401
    _msg = 'Authentication Failed'

    def __str__(self):
        return self._msg


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


class UnknownUserException(APIException):

    def __init__(self, user_uuid):
        msg = 'No such user: "{}"'.format(user_uuid)
        details = dict(uuid=user_uuid)
        super(UnknownUserException, self).__init__(404, msg, 'unknown_user', details, 'users')


class UnknownUsernameException(Exception):

    def __init__(self, username):
        msg = 'No such user: "{}"'.format(username)
        super(UnknownUsernameException, self).__init__(msg)


class UserParamException(APIException):

    def __init__(self, message, details=None):
        super(UserParamException, self).__init__(400, message, 'invalid_data', details, 'users')

    @classmethod
    def from_errors(cls, errors):
        for field, infos in errors.iteritems():
            if not isinstance(infos, list):
                infos = [infos]
            for info in infos:
                return cls(info['message'], {field: info})


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

    def __str__(self):
        return 'No such policy'


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
