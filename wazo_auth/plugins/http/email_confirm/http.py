# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from wazo_auth import http


class EmailConfirm(http.AuthResource):

    def __init__(self, email_service):
        self.email_service = email_service

    @http.required_acl('auth.emails.{email_uuid}.confirm.edit')
    def put(self, email_uuid):
        self.email_service.confirm(email_uuid)
        return '', 204
