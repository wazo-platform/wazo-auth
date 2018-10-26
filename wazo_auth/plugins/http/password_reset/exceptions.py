# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from wazo_auth.exceptions import _BaseParamException


class PasswordResetException(_BaseParamException):

    resource = 'reset'

    def __init__(self, message, details=None):
        super(PasswordResetException, self).__init__(message)

    @classmethod
    def from_errors(cls, errors):
        if list(errors.keys()) == ['_schema']:
            return cls(errors['_schema'])
        else:
            return super(PasswordResetException, cls).from_errors(errors)
