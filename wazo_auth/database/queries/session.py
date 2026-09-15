# Copyright 2019-2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime, timezone

from sqlalchemy import and_, text

from ...helpers import is_uuid
from ..models import RefreshToken, Session, Token
from .base import BaseDAO, PaginatorMixin


class SessionDAO(PaginatorMixin, BaseDAO):
    column_map = {
        'mobile': Session.mobile,
        'issued_at': Token.issued_t,
        'expires_at': Token.expire_t,
        'user_agent': Token.user_agent,
        'remote_addr': Token.remote_addr,
        'client_id': RefreshToken.client_id,
    }

    def list_(self, tenant_uuids=None, user_uuid=None, **kwargs):
        query = self._session_query(tenant_uuids, user_uuid)
        if query is None:
            return []

        query = self._paginator.update_query(query, **kwargs)

        return [
            {
                'uuid': r.Session.uuid,
                'mobile': r.Session.mobile,
                'tenant_uuid': r.Session.tenant_uuid,
                'user_uuid': r.Token.auth_id if is_uuid(r.Token.auth_id) else None,
                'user_agent': r.Token.user_agent,
                'remote_addr': r.Token.remote_addr,
                'acl': r.Token.acl,
                'issued_at': self._to_datetime(r.Token.issued_t),
                'expires_at': self._to_datetime(r.Token.expire_t),
                'client_id': r.client_id,
            }
            for r in query.all()
        ]

    def count(self, tenant_uuids=None, user_uuid=None, **kwargs):
        query = self._session_query(tenant_uuids, user_uuid)
        if query is None:
            return 0

        return query.count()

    def _session_query(self, tenant_uuids, user_uuid):
        filter_ = text('true')
        if tenant_uuids is not None:
            if not tenant_uuids:
                return None

            filter_ = and_(filter_, Session.tenant_uuid.in_(tenant_uuids))

        if user_uuid is not None:
            filter_ = and_(filter_, Token.auth_id == str(user_uuid))

        # a session references a single token, enforced by a unique constraint
        return (
            self.session.query(Session, Token, RefreshToken.client_id)
            .select_from(Session)
            .join(Token)
            .outerjoin(RefreshToken, RefreshToken.uuid == Token.refresh_token_uuid)
            .filter(filter_)
        )

    @staticmethod
    def _to_datetime(timestamp):
        if timestamp is None:
            return None
        return datetime.fromtimestamp(timestamp, timezone.utc)

    def delete(self, session_uuid, tenant_uuids):
        filter_ = Session.uuid == str(session_uuid)
        if not tenant_uuids:
            return {}, {}
        filter_ = and_(filter_, Session.tenant_uuid.in_(tenant_uuids))

        session = self.session.query(Session).filter(filter_).first()
        if not session:
            return {}, {}

        token = session.token
        token_result = {'uuid': token.uuid, 'auth_id': token.auth_id} if token else {}

        session_result = {'uuid': session.uuid, 'tenant_uuid': session.tenant_uuid}
        self.session.query(Session).filter(filter_).delete(synchronize_session=False)
        self.session.flush()

        return session_result, token_result

    def delete_by_user(self, user_uuid):
        query = (
            self.session.query(Session.uuid)
            .select_from(Token)
            .join(Token.session)
            .filter(Token.auth_id == str(user_uuid))
        )
        session_uuids = [row[0] for row in query.all()]
        self.session.query(Session).filter(Session.uuid.in_(session_uuids)).delete()
        self.session.flush()

        return [{'uuid': uuid} for uuid in session_uuids]

    def delete_by_refresh_token_uuid(self, refresh_token_uuid: str) -> list[str]:
        query = (
            self.session.query(Session.uuid)
            .select_from(Token)
            .join(Token.session)
            .filter(Token.refresh_token_uuid == str(refresh_token_uuid))
        )
        session_uuids = [row[0] for row in query.all()]
        if not session_uuids:
            return []

        # FK auth_token.session_uuid ON DELETE CASCADE removes matching tokens.
        self.session.query(Session).filter(Session.uuid.in_(session_uuids)).delete()
        self.session.flush()

        return session_uuids
