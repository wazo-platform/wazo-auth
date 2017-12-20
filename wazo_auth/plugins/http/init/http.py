# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import os

from flask import request
from wazo_auth import exceptions, http
from .schemas import InitPostSchema


class Init(http.ErrorCatchingResource):

    def __init__(self, policy_service, user_service, config):
        self.user_service = user_service
        self._init_key_filename = config['init_key_filename']
        policy_name = config['init_policy_name']
        self._policy_uuid = policy_service.list(name=policy_name)[0]['uuid']
        self._key = None
        with open(self._init_key_filename, 'r') as f:
            for line in f:
                self._key = line.strip()
                break

    def post(self):
        args, errors = InitPostSchema().load(request.get_json())
        if errors:
            raise exceptions.InitParamException.from_errors(errors)

        if not self._key:
            raise exceptions.AuthenticationFailedException()

        if args.pop('key') != self._key:
            raise exceptions.AuthenticationFailedException()

        result = self.user_service.new_user(**args)
        self.user_service.add_policy(result['uuid'], self._policy_uuid)

        self._key = None
        try:
            os.remove(self._init_key_filename)
        except OSError:
            pass

        return result, 200
