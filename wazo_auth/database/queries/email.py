# Copyright 2017-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth import exceptions

from .base import BaseDAO
from ..models import Email


class EmailDAO(BaseDAO):
    def create(self, address, confirmed=False):
        email = Email(address=address, confirmed=confirmed)
        self.session.add(email)
        self.session.flush()
        return email.uuid

    def confirm(self, email_uuid):
        filter_ = Email.uuid == str(email_uuid)
        nb_updated = (
            self.session.query(Email).filter(filter_).update({'confirmed': True})
        )

        if not nb_updated:
            raise exceptions.UnknownEmailException(email_uuid)

    def delete(self, email_uuid):
        filter_ = Email.uuid == str(email_uuid)
        nb_deleted = self.session.query(Email).filter(filter_).delete()

        if not nb_deleted:
            raise exceptions.UnknownEmailException(email_uuid)
