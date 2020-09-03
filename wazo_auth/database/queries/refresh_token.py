# Copyright 2019-2020 The Wazo Authors  (see the AUTHORS file)
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
        'mobile': RefreshToken.mobile,
    }

    def count(self, user_uuid=None, tenant_uuids=None, filtered=False, **search_params):
        filter_ = text('true')

        if user_uuid is not None:
            filter_ = and_(filter_, RefreshToken.user_uuid == user_uuid)

        if tenant_uuids is not None:
            if not tenant_uuids:
                filter_ = and_(filter_, text('false'))
            else:
                filter_ = and_(filter_, RefreshToken.tenant_uuid.in_(tenant_uuids))

        if filtered is not False:
            strict_filter = self.new_strict_filter(**search_params)
            search_filter = self.new_search_filter(**search_params)
            filter_ = and_(filter_, strict_filter, search_filter)

        return self.session.query(RefreshToken).filter(filter_).count()

    def create(self, body):
        refresh_token = RefreshToken(**body)
        self.session.add(refresh_token)
        try:
            self.session.flush()
        except exc.IntegrityError as e:
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                constraint = e.orig.diag.constraint_name
                if constraint == 'auth_refresh_token_client_id_user_uuid':
                    self.session.rollback()
                    raise exceptions.DuplicatedRefreshTokenException(
                        body['user_uuid'],
                        body['client_id'],
                    )
            raise

        return refresh_token.uuid

    def delete(self, tenant_uuids, user_uuid, client_id):
        filter_ = and_(
            RefreshToken.client_id == client_id,
            RefreshToken.user_uuid == user_uuid,
            RefreshToken.tenant_uuid.in_(tenant_uuids),
        )

        nb_deleted = (
            self.session.query(RefreshToken)
            .filter(filter_)
            .delete(synchronize_session=False)
        )

        self.session.flush()
        if not nb_deleted:
            raise exceptions.UnknownRefreshToken(client_id)

    def get(self, refresh_token, client_id):
        filter_ = and_(
            RefreshToken.client_id == client_id, RefreshToken.uuid == refresh_token
        )
        query = self.session.query(RefreshToken).filter(filter_)
        for refresh_token in query.all():
            return {
                'backend_name': refresh_token.backend,
                'login': refresh_token.login,
            }

        raise exceptions.UnknownRefreshToken(client_id)

    def get_by_user(self, tenant_uuids, user_uuid, client_id):
        filter_ = and_(
            RefreshToken.client_id == client_id,
            RefreshToken.user_uuid == user_uuid,
            RefreshToken.tenant_uuid.in_(tenant_uuids),
        )

        query = self.session.query(
            RefreshToken.tenant_uuid, RefreshToken.mobile
        ).filter(filter_)
        for refresh_token in query.all():
            return {
                'tenant_uuid': refresh_token.tenant_uuid,
                'mobile': refresh_token.mobile,
            }

        raise exceptions.UnknownRefreshToken(client_id)

    def list_(self, user_uuid=None, tenant_uuids=None, **search_params):
        filter_ = text('true')

        if user_uuid is not None:
            filter_ = and_(filter_, RefreshToken.user_uuid == user_uuid)

        if tenant_uuids is not None:
            if not tenant_uuids:
                filter_ = and_(filter_, text('false'))
            else:
                filter_ = and_(filter_, RefreshToken.tenant_uuid.in_(tenant_uuids))

        strict_filter = self.new_strict_filter(**search_params)
        search_filter = self.new_search_filter(**search_params)
        filter_ = and_(filter_, strict_filter, search_filter)

        query = self.session.query(RefreshToken).filter(filter_)
        query = self._paginator.update_query(query, **search_params)

        refresh_tokens = []
        for refresh_token in query.all():
            refresh_tokens.append(
                {
                    'uuid': refresh_token.uuid,
                    'user_uuid': refresh_token.user_uuid,
                    'tenant_uuid': refresh_token.tenant_uuid,
                    'client_id': refresh_token.client_id,
                    'mobile': refresh_token.mobile,
                    'created_at': refresh_token.created_at,
                    'user_agent': refresh_token.user_agent,
                    'remote_addr': refresh_token.remote_addr,
                }
            )
        return refresh_tokens

    def get_existing_refresh_token(self, client_id, user_uuid):
        filter_ = and_(
            RefreshToken.client_id == client_id, RefreshToken.user_uuid == user_uuid
        )
        query = self.session.query(RefreshToken).filter(filter_)
        for refresh_token in query.all():
            return refresh_token.uuid
