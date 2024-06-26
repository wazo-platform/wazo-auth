# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import exc

from ... import exceptions
from ..models import SAMLConfig
from .base import BaseDAO


class SAMLConfigDAO(BaseDAO):
    def list(self) -> list[SAMLConfig]:
        return self.session.query(SAMLConfig).all()

    def get(self, tenant_uuid):
        saml_config = (
            self.session.query(SAMLConfig)
            .filter(SAMLConfig.tenant_uuid == tenant_uuid)
            .first()
        )
        if saml_config:
            return {
                'domain_uuid': saml_config.domain_uuid,
                'tenant_uuid': saml_config.tenant_uuid,
                'entity_id': saml_config.entity_id,
                'idp_metadata': saml_config.idp_metadata,
            }
        raise exceptions.UnknownSAMLConfigException(tenant_uuid)

    def create(
        self,
        tenant_uuid,
        domain_uuid,
        entity_id,
        idp_metadata,
    ):
        saml_config = SAMLConfig(
            tenant_uuid=tenant_uuid,
            domain_uuid=domain_uuid,
            entity_id=entity_id,
            idp_metadata=idp_metadata,
        )
        self.session.add(saml_config)
        try:
            self.session.flush()
        except exc.IntegrityError as e:
            self.session.rollback()
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                raise exceptions.DuplicatedSAMLConfigException(tenant_uuid)
            raise
        return saml_config.tenant_uuid

    def update(self, tenant_uuid, **kwargs):
        filter_ = SAMLConfig.tenant_uuid == str(tenant_uuid)
        saml_config = self.get(tenant_uuid)
        saml_config.update(kwargs)

        try:
            self.session.query(SAMLConfig).filter(filter_).update(saml_config)
            self.session.flush()
        except exc.IntegrityError:
            self.session.rollback()
            raise

    def delete(self, tenant_uuid) -> None:
        filter_ = SAMLConfig.tenant_uuid == str(tenant_uuid)
        self.session.query(SAMLConfig).filter(filter_).delete(synchronize_session=False)
        self.session.flush()

    def exists(self, tenant_uuid):
        filter_ = SAMLConfig.tenant_uuid == str(tenant_uuid)
        return self.session.query(SAMLConfig).filter(filter_).count() > 0
