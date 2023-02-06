# Copyright 2018-2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth.exceptions import _BaseParamException


class PasswordResetException(_BaseParamException):
    resource = 'reset'

    def __init__(self, message, details=None):
        super().__init__(message)

    @classmethod
    def from_errors(cls, errors):
        if list(errors.keys()) == ['_schema']:
            return cls(errors['_schema'])
        else:
            return super().from_errors(errors)
