# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from wazo_auth import http

logger = logging.getLogger(__name__)


class UserEmailConfirm(http.AuthResource):

    @http.required_acl('auth.users.{user_uuid}.emails.{email_uuid}.confirm.read')
    def get(self, user_uuid, email_uuid):
        logger.debug('sending a new email confirmation user_uuid: %s email_uuid: %s',
                     user_uuid, email_uuid)
        return '', 204
