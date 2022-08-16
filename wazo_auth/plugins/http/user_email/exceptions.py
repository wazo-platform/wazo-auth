# Copyright 2018-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth.exceptions import APIException


class EmailAlreadyConfirmedException(APIException):
    def __init__(self, email_uuid):
        msg = f'This email already confirmed: "{email_uuid}"'
        details = {'uuid': str(email_uuid)}
        super().__init__(409, msg, 'conflict', details, 'emails')
