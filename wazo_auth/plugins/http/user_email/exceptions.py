# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from wazo_auth.exceptions import APIException


class EmailAlreadyConfirmedException(APIException):

    def __init__(self, email_uuid):
        msg = 'This email already confirmed: "{}"'.format(email_uuid)
        details = {'uuid': str(email_uuid)}
        super(EmailAlreadyConfirmedException, self).__init__(409, msg, 'conflict', details, 'emails')
