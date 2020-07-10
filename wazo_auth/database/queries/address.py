# Copyright 2018-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth import exceptions

from .base import BaseDAO
from ..models import Address


class AddressDAO(BaseDAO):
    def delete(self, address_id):
        self.session.query(Address).filter(Address.id_ == address_id).delete()
        self.session.flush()

    def get(self, address_id):
        for row in self.session.query(Address).filter(Address.id_ == address_id).all():
            return dict(
                line_1=row.line_1,
                line_2=row.line_2,
                city=row.city,
                state=row.state,
                country=row.country,
                zip_code=row.zip_code,
            )

        raise exceptions.UnknownAddressException(address_id)

    def new(self, tenant_uuid=None, **kwargs):
        if self._address_is_empty(**kwargs):
            return None

        address = Address(tenant_uuid=tenant_uuid, **kwargs)
        self.session.add(address)
        self.session.flush()
        return address.id_

    def update(self, address_id, **kwargs):
        if self._address_is_empty(**kwargs):
            self.delete(address_id)
            self.session.flush()
            return None

        self.session.query(Address).filter(Address.id_ == address_id).update(kwargs)
        self.session.flush()
        return address_id

    def _address_is_empty(self, **kwargs):
        for value in kwargs.values():
            if value is not None:
                return False
        return True
