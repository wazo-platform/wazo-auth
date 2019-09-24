# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import and_, exc, text

from wazo_auth import exceptions

from . import filters
from .base import BaseDAO
from ..models import RefreshToken


class RefreshTokenDAO(filters.FilterMixin, BaseDAO):

    strict_filter = filters.refresh_token_strict_filter
    search_filter = filters.refresh_token_search_filter

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
                    return self._get_existing_refresh_token(
                        body['client_id'], body['user_uuid']
                    )
            raise

        return refresh_token.uuid

    def get(self, refresh_token, client_id):
        filter_ = and_(
            RefreshToken.client_id == client_id, RefreshToken.uuid == refresh_token
        )
        query = self.session.query(RefreshToken).filter(filter_)
        for refresh_token in query.all():
            return {'backend_name': refresh_token.backend, 'login': refresh_token.login}

        raise exceptions.UnknownRefreshToken(refresh_token, client_id)

    def _get_existing_refresh_token(self, client_id, user_uuid):
        filter_ = and_(
            RefreshToken.client_id == client_id, RefreshToken.user_uuid == user_uuid
        )
        query = self.session.query(RefreshToken).filter(filter_)
        for refresh_token in query.all():
            return refresh_token.uuid
