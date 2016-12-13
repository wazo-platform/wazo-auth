# -*- coding: utf-8 -*-
#
# Copyright 2016 The Wazo Authors  (see the AUTHORS file)
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

from .token import Token, UnknownTokenException


class Storage(object):

    def __init__(self, crud):
        self._crud = crud

    def get_token(self, token_id):
        token_data = self._crud.get(token_id)
        if not token_data:
            raise UnknownTokenException()

        id_ = token_data.pop('uuid')
        return Token(id_, **token_data)

    def create_token(self, token_payload):
        token_uuid = self._crud.create(token_payload)
        return Token(token_uuid, **token_payload.__dict__)

    def remove_token(self, token_id):
        self._crud.delete(token_id)

    @classmethod
    def from_config(cls, config):
        pass


class _TokenCRUD(object):

    pass
