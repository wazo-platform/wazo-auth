# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import and_, exc, text

from wazo_auth import exceptions

from . import filters
from .base import BaseDAO, PaginatorMixin
from ..models import RefreshToken


class RefreshTokenDAO(filters.FilterMixin, PaginatorMixin, BaseDAO):

    strict_filter = filters.refresh_token_strict_filter
    search_filter = filters.refresh_token_search_filter
    column_map = {
        'created_at': RefreshToken.created_at,
        'client_id': RefreshToken.client_id,
    }

    def count(self, user_uuid, tenant_uuids=None, filtered=False, **search_params):
        filter_ = RefreshToken.user_uuid == user_uuid
        if tenant_uuids is not None:
            if not tenant_uuids:
                filter_ = and_(filter_, text('false'))
            else:
                filter_ = and_(filter_, RefreshToken.tenant_uuid.in_(tenant_uuids))

        if filtered is not False:
            strict_filter = self.new_strict_filter(**search_params)
            search_filter = self.new_search_filter(**search_params)
            filter_ = and_(filter_, strict_filter, search_filter)

        with self.new_session() as session:
            return session.query(RefreshToken).filter(filter_).count()

    def create(self, body):
        refresh_token = RefreshToken(**body)
        with self.new_session() as session:
            session.add(refresh_token)
            try:
                session.flush()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    constraint = e.orig.diag.constraint_name
                    if constraint == 'auth_refresh_token_client_id_user_uuid':
                        session.rollback()
                        return self._get_existing_refresh_token(
                            session, body['client_id'], body['user_uuid']
                        )
                raise

            return refresh_token.uuid

    def delete(self, tenant_uuids, user_uuid, client_id):
        filter_ = and_(
            RefreshToken.client_id == client_id,
            RefreshToken.user_uuid == user_uuid,
            RefreshToken.tenant_uuid.in_(tenant_uuids),
        )

        with self.new_session() as session:
            nb_deleted = (
                session.query(RefreshToken)
                .filter(filter_)
                .delete(synchronize_session=False)
            )

            if not nb_deleted:
                raise exceptions.UnknownRefreshToken(client_id)

    def get(self, refresh_token, client_id):
        with self.new_session() as session:
            filter_ = and_(
                RefreshToken.client_id == client_id, RefreshToken.uuid == refresh_token
            )
            query = session.query(RefreshToken).filter(filter_)
            for refresh_token in query.all():
                return {'backend_name': refresh_token.backend, 'login': refresh_token.login}

            raise exceptions.UnknownRefreshToken(client_id)

    def list_(self, user_uuid, tenant_uuids=None, **search_params):
        filter_ = RefreshToken.user_uuid == user_uuid
        if tenant_uuids is not None:
            if not tenant_uuids:
                filter_ = and_(filter_, text('false'))
            else:
                filter_ = and_(filter_, RefreshToken.tenant_uuid.in_(tenant_uuids))

        strict_filter = self.new_strict_filter(**search_params)
        search_filter = self.new_search_filter(**search_params)
        filter_ = and_(filter_, strict_filter, search_filter)

        with self.new_session() as session:
            query = session.query(RefreshToken).filter(filter_)
            query = self._paginator.update_query(query, **search_params)

            return query.all()

    def _get_existing_refresh_token(self, session, client_id, user_uuid):
        filter_ = and_(
            RefreshToken.client_id == client_id, RefreshToken.user_uuid == user_uuid
        )
        with self.new_session() as session:
            query = session.query(RefreshToken).filter(filter_)
            for refresh_token in query.all():
                return refresh_token.uuid
