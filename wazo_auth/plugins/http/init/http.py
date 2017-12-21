# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging
import os

from contextlib import contextmanager
from flask import request
from wazo_auth import exceptions, http
from .schemas import InitPostSchema

logger = logging.getLogger(__name__)


@contextmanager
def delete_after_usage(filename):
    try:
        with open(filename, 'r') as f:
            for line in f:
                key = line.strip()
                break
    except IOError:
        raise exceptions.AuthenticationFailedException()

    # Do not wrap this call in a try finally
    # We do not want to erase the key if the operaion fail
    yield key

    try:
        os.remove(filename)
    except OSError:
        logger.info('failed to remove the key file')


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

        with delete_after_usage(self._init_key_filename) as key:
            if args.pop('key') != key:
                raise exceptions.AuthenticationFailedException()

            result = self._user_service.new_user(**args)
            policy_uuid = self._policy_service.list(name=self._policy_name)[0]['uuid']
            self._user_service.add_policy(result['uuid'], policy_uuid)

        return result, 200
