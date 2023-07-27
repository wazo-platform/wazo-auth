# Copyright 2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import exc

from .base import BaseDAO
from ..models import CASConfig
from ... import exceptions


class CASConfigDAO(BaseDAO):
    def get(self, tenant_uuid):
        cas_config = (
            self.session.query(CASConfig)
            .filter(CASConfig.tenant_uuid == tenant_uuid)
            .first()
        )
        if cas_config:
            return {
                'tenant_uuid': cas_config.tenant_uuid,
                'server_url': cas_config.server_url,
                'service_url': cas_config.service_url,
                'user_email_attribute': cas_config.user_email_attribute,
            }
        raise exceptions.UnknownCASConfigException(tenant_uuid)

    def create(
        self,
        tenant_uuid,
        server_url,
        service_url,
        user_email_attribute,
    ):
        cas_config = CASConfig(
            tenant_uuid=tenant_uuid,
            server_url=server_url,
            service_url=service_url,
            user_email_attribute=user_email_attribute,
        )
        self.session.add(cas_config)
        try:
            self.session.flush()
        except exc.IntegrityError as e:
            self.session.rollback()
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                raise exceptions.DuplicatedCASConfigException(tenant_uuid)
            raise
        return cas_config.tenant_uuid

    def update(self, tenant_uuid, **kwargs):
        filter_ = CASConfig.tenant_uuid == str(tenant_uuid)
        cas_config = self.get(tenant_uuid)
        cas_config.update(kwargs)

        try:
            self.session.query(CASConfig).filter(filter_).update(cas_config)
            self.session.flush()
        except exc.IntegrityError:
            self.session.rollback()
            raise

    def delete(self, tenant_uuid):
        filter_ = CASConfig.tenant_uuid == str(tenant_uuid)
        self.session.query(CASConfig).filter(filter_).delete(synchronize_session=False)
        self.session.flush()

    def exists(self, tenant_uuid):
        filter_ = CASConfig.tenant_uuid == str(tenant_uuid)
        return self.session.query(CASConfig).filter(filter_).count() > 0
