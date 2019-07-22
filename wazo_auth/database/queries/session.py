# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import text, and_

from .base import BaseDAO, PaginatorMixin
from ..models import Session, Token


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

        with self.new_session() as s:
            query = s.query(Session, Token).join(Token).filter(filter_)
            query = self._paginator.update_query(query, **kwargs)

            return [
                {
                    'uuid': result.Session.uuid,
                    'mobile': result.Session.mobile,
                    'tenant_uuid': result.Session.tenant_uuid,
                    'user_uuid': result.Token.auth_id,
                }
                for result in query.all()
            ]

    def count(self, tenant_uuids=None, **kwargs):
        filter_ = text('true')

        if tenant_uuids is not None:
            if not tenant_uuids:
                return 0
            filter_ = and_(filter_, Session.tenant_uuid.in_(tenant_uuids))

        with self.new_session() as s:
            return s.query(Session).join(Token).filter(filter_).count()

    def delete(self, session_uuid, tenant_uuids):
        filter_ = Session.uuid == str(session_uuid)
        if not tenant_uuids:
            return {}, {}
        filter_ = and_(filter_, Session.tenant_uuid.in_(tenant_uuids))

        with self.new_session() as s:
            session = s.query(Session).filter(filter_).first()
            if not session:
                return {}, {}

            token_result = {}
            for token in session.tokens:
                token_result = {'uuid': token.uuid, 'auth_id': token.auth_id}
                break

            session_result = {'uuid': session.uuid, 'tenant_uuid': session.tenant_uuid}
            s.query(Session).filter(filter_).delete(synchronize_session=False)

        return session_result, token_result
