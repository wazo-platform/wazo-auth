# Copyright 2017-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth import exceptions

from .base import BaseDAO
from ..models import Email


class EmailDAO(BaseDAO):
    def confirm(self, email_uuid):
        filter_ = Email.uuid == str(email_uuid)
        nb_updated = (
            self.session.query(Email).filter(filter_).update({'confirmed': True})
        )
        self.session.flush()

        if not nb_updated:
            raise exceptions.UnknownEmailException(email_uuid)
