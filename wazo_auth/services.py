# -*- coding: utf-8 -*-
#
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import binascii
import hashlib
import logging
import os

logger = logging.getLogger(__name__)


class UserService(object):

    def __init__(self, storage, encrypter=None):
        self._storage = storage
        self._encrypter = encrypter or PasswordEncrypter()

    def count_users(self, **kwargs):
        return 0

    def list_users(self, **kwargs):
        return []

    def new_user(self, *args, **kwargs):
        password = kwargs.pop('password')
        salt, hash_ = self._encrypter.encrypt_password(password)
        logger.info('creating a new user with params: %s', kwargs)  # log after poping the password
        # a confirmation email should be sent
        return self._storage.user_create(*args, salt=salt, hash_=hash_, **kwargs)


class PasswordEncrypter(object):

    _salt_len = 64
    _hash_algo = 'sha512'
    _iterations = 250000

    def encrypt_password(self, password):
        password_bytes = password.encode('utf-8')
        salt = os.urandom(self._salt_len)
        dk = hashlib.pbkdf2_hmac(self._hash_algo, password_bytes, salt, self._iterations)
        hash_ = binascii.hexlify(dk)

        return salt, hash_
