# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import text, and_

from .base import BaseDAO, PaginatorMixin
from ..models import (
    Session,
    Tenant,
    Token,
)


class SessionDAO(PaginatorMixin, BaseDAO):

    column_map = {'mobile': Session.mobile}

    def create(self, **kwargs):
        if not kwargs.get('tenant_uuid'):
            with self.new_session() as s:
                filter_ = Tenant.uuid == Tenant.parent_uuid
                kwargs['tenant_uuid'] = s.query(Tenant).filter(filter_).first().uuid

        session = Session(**kwargs)
        with self.new_session() as s:
            s.add(session)
            s.commit()
            return session.uuid

    def list_(self, tenant_uuids=None, **kwargs):
        filter_ = text('true')
        if tenant_uuids is not None:
            if not tenant_uuids:
                return []

            filter_ = Session.tenant_uuid.in_(tenant_uuids)

        with self.new_session() as s:
            query = s.query(Session).filter(filter_)
            query = self._paginator.update_query(query, **kwargs)

            return [{
                'uuid': session.uuid,
                'mobile': session.mobile,
                'tenant_uuid': session.tenant_uuid,
            } for session in query.all()]

    def count(self, tenant_uuids=None, **kwargs):
        filter_ = text('true')

        if tenant_uuids is not None:
            if not tenant_uuids:
                return 0
            filter_ = and_(filter_, Session.tenant_uuid.in_(tenant_uuids))

        with self.new_session() as s:
            return s.query(Session).filter(filter_).count()

    def delete_expired(self):
        with self.new_session() as s:
            subquery = s.query(Session.uuid).outerjoin(Token).filter(Token.uuid == None)
            query = s.query(Session).filter(Session.uuid.in_(subquery.subquery()))
            query.delete(synchronize_session=False)
