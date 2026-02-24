# Copyright 2019-2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import and_, text

from ...helpers import is_uuid
from ..models import Session, Token
from .base import BaseDAO, PaginatorMixin


class SessionDAO(PaginatorMixin, BaseDAO):
    column_map = {'mobile': Session.mobile}

    def list_(self, tenant_uuids=None, user_uuid=None, **kwargs):
        filter_ = text('true')
        if tenant_uuids is not None:
            if not tenant_uuids:
                return []

            filter_ = and_(filter_, Session.tenant_uuid.in_(tenant_uuids))

        if user_uuid is not None:
            filter_ = and_(filter_, Token.auth_id == str(user_uuid))

        query = self.session.query(Session, Token).join(Token).filter(filter_)
        query = self._paginator.update_query(query, **kwargs)

        return [
            {
                'uuid': r.Session.uuid,
                'mobile': r.Session.mobile,
                'tenant_uuid': r.Session.tenant_uuid,
                'user_uuid': r.Token.auth_id if is_uuid(r.Token.auth_id) else None,
            }
            for r in query.all()
        ]

    def count(self, tenant_uuids=None, user_uuid=None, **kwargs):
        filter_ = text('true')

        if tenant_uuids is not None:
            if not tenant_uuids:
                return 0
            filter_ = and_(filter_, Session.tenant_uuid.in_(tenant_uuids))

        if user_uuid is not None:
            filter_ = and_(filter_, Session.tokens.any(auth_id=str(user_uuid)))

        return self.session.query(Session).join(Token).filter(filter_).count()

    def delete(self, session_uuid, tenant_uuids):
        filter_ = Session.uuid == str(session_uuid)
        if not tenant_uuids:
            return {}, {}
        filter_ = and_(filter_, Session.tenant_uuid.in_(tenant_uuids))

        session = self.session.query(Session).filter(filter_).first()
        if not session:
            return {}, {}

        token_result = {}
        for token in session.tokens:
            token_result = {'uuid': token.uuid, 'auth_id': token.auth_id}
            break

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
