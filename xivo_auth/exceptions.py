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


class ManagerException(Exception):
    pass


class InvalidInputException(ManagerException):

    code = 400

    def __init__(self, field):
        super(InvalidInputException, self).__init__()
        self._field = field

    def __str__(self):
        return 'Invalid value supplied for field: {}'.format(self._field)


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


class DuplicatePolicyException(ManagerException):

    code = 409

    def __init__(self, name):
        super(DuplicatePolicyException, self).__init__()
        self._name = name

    def __str__(self):
        return 'Policy "{}" already exists'.format(self._name)


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


class RabbitMQConnectionException(ManagerException):

    code = 500

    def __str__(self):
        return 'Connection to rabbitmq failed'
