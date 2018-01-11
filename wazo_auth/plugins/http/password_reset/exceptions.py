# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from wazo_auth.exceptions import APIException


class PasswordResetException(APIException):

    def __init__(self, message, details=None):
        super(PasswordResetException, self).__init__(400, message, 'invalid_param', {}, 'reset')

    @classmethod
    def from_errors(cls, errors):
        return cls(errors['_schema'])
