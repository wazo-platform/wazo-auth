# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging
import os

from flask import request
from wazo_auth import exceptions, http
from .schemas import InitPostSchema

logger = logging.getLogger(__name__)


class Init(http.ErrorCatchingResource):

    def __init__(self, policy_service, user_service, config):
        self._user_service = user_service
        self._policy_service = policy_service
        self._init_key_filename = config['init_key_filename']
        self._policy_name = config['init_policy_name']

    def post(self):
        args, errors = InitPostSchema().load(request.get_json())
        if errors:
            raise exceptions.InitParamException.from_errors(errors)

        try:
            with open(self._init_key_filename, 'r') as f:
                for line in f:
                    key = line.strip()
                    break
        except IOError:
            raise exceptions.AuthenticationFailedException()

        if args.pop('key') != key:
            raise exceptions.AuthenticationFailedException()

        result = self._user_service.new_user(**args)
        policy_uuid = self._policy_service.list(name=self._policy_name)[0]['uuid']
        self._user_service.add_policy(result['uuid'], policy_uuid)

        try:
            os.remove(self._init_key_filename)
        except OSError:
            logger.info('failed to remove the key file')

        return result, 200
