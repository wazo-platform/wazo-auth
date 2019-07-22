# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import and_, exc

from wazo_auth import exceptions

from .base import BaseDAO
from ..models import RefreshToken


class RefreshTokenDAO(BaseDAO):
    def create(self, body):
        refresh_token = RefreshToken(**body)
        with self.new_session() as s:
            s.add(refresh_token)
            try:
                s.flush()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    constraint = e.orig.diag.constraint_name
                    if constraint == 'auth_refresh_token_client_id_user_uuid':
                        s.rollback()
                        return self._get_existing_refresh_token(
                            body['client_id'], body['user_uuid']
                        )
                raise

            return refresh_token.uuid

    def get(self, refresh_token, client_id):
        filter_ = and_(
            RefreshToken.client_id == client_id, RefreshToken.uuid == refresh_token
        )
        with self.new_session() as s:
            query = s.query(RefreshToken).filter(filter_)
            for refresh_token in query.all():
                return {
                    'backend_name': refresh_token.backend,
                    'login': refresh_token.login,
                }

        raise exceptions.UnknownRefreshToken(refresh_token, client_id)

    def _get_existing_refresh_token(self, client_id, user_uuid):
        filter_ = and_(
            RefreshToken.client_id == client_id, RefreshToken.user_uuid == user_uuid
        )
        with self.new_session() as s:
            query = s.query(RefreshToken).filter(filter_)
            for refresh_token in query.all():
                return refresh_token.uuid
