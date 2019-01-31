# Copyright 2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from .base import BaseDAO
from ..models import Session as SessionModel


class SessionDAO(BaseDAO):

    def create(self, body=None):
        session = SessionModel()
        with self.new_session() as s:
            s.add(session)
            s.commit()
            return session.uuid
