# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from wazo_auth import exceptions

from .base import BaseDAO
from ..models import Email


class EmailDAO(BaseDAO):

    def create(self, address, confirmed=False):
        email = Email(address=address, confirmed=confirmed)
        with self.new_session() as s:
            s.add(email)
            s.flush()
            return email.uuid

    def confirm(self, email_uuid):
        filter_ = Email.uuid == str(email_uuid)
        with self.new_session() as s:
            nb_updated = s.query(Email).filter(filter_).update({'confirmed': True})

            if not nb_updated:
                raise exceptions.UnknownEmailException(email_uuid)

    def delete(self, email_uuid):
        filter_ = Email.uuid == str(email_uuid)
        with self.new_session() as s:
            nb_deleted = s.query(Email).filter(filter_).delete()

        if not nb_deleted:
            raise exceptions.UnknownEmailException(email_uuid)
