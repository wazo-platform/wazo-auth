# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from .base import BaseDAO
from ..models import (
    Session,
    Tenant,
    Token,
)


class SessionDAO(BaseDAO):

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

    def delete_expired(self):
        with self.new_session() as s:
            subquery = s.query(Session.uuid).outerjoin(Token).filter(Token.uuid == None)
            query = s.query(Session).filter(Session.uuid.in_(subquery.subquery()))
            query.delete(synchronize_session=False)
