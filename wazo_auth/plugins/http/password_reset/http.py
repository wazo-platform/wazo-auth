# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from flask import request
from wazo_auth import http
from .schemas import PasswordResetQueryParameters
from .exceptions import PasswordResetException

logger = logging.getLogger(__name__)


class PasswordReset(http.ErrorCatchingResource):

    def get(self):
        args, errors = PasswordResetQueryParameters().load(request.args)
        if errors:
            raise PasswordResetException.from_errors(errors)

        logger.debug('resetting password for %s', args['username'] or args['email'])

        return '', 204
