# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from ..models import Domain
from .base import BaseDAO


class DomainDAO(BaseDAO):
    def list(self) -> list[Domain]:
        return self.session.query(Domain).all()
