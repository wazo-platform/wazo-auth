# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Any

from sqlalchemy import exc

from ... import exceptions
from ..models import SAMLConfig
from .base import BaseDAO


class SAMLConfigDAO(BaseDAO):
    def list(self) -> list[SAMLConfig]:
        return self.session.query(SAMLConfig).all()

    def _forge_return(self, saml_config: SAMLConfig) -> dict[str, Any]:
        return {
            'domain_uuid': saml_config.domain_uuid,
            'tenant_uuid': saml_config.tenant_uuid,
            'entity_id': saml_config.entity_id,
            'idp_metadata': saml_config.idp_metadata,
            'acs_url': saml_config.acs_url,
        }

    def get(self, tenant_uuid):
        saml_config = (
            self.session.query(SAMLConfig)
            .filter(SAMLConfig.tenant_uuid == tenant_uuid)
            .first()
        )
        if saml_config:
            return self._forge_return(saml_config)
        raise exceptions.UnknownSAMLConfigException(tenant_uuid)

    def create(
        self,
        tenant_uuid,
        domain_uuid,
        entity_id,
        idp_metadata,
        acs_url,
    ) -> dict[str, Any]:
        saml_config = SAMLConfig(
            tenant_uuid=tenant_uuid,
            domain_uuid=domain_uuid,
            entity_id=entity_id,
            idp_metadata=idp_metadata,
            acs_url=acs_url,
        )
        self.session.add(saml_config)
        try:
            self.session.flush()
        except exc.IntegrityError as e:
            self.session.rollback()
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                raise exceptions.DuplicatedSAMLConfigException(tenant_uuid)
            if e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                raise exceptions.SAMLConfigParameterException(
                    tenant_uuid,
                    'Domain_uuid violates foreign key constraint, domain not in requested tenant',
                    409,
                )
            else:
                raise exceptions.SAMLConfigParameterException(
                    tenant_uuid, f'Unexpected error on update {e.orig.pgcode}', 500
                )
        return self._forge_return(saml_config)

    def update(self, tenant_uuid, **kwargs):
        filter_ = SAMLConfig.tenant_uuid == str(tenant_uuid)
        saml_config = self.get(tenant_uuid)
        saml_config.update(kwargs)

        try:
            self.session.query(SAMLConfig).filter(filter_).update(saml_config)
            self.session.flush()
        except exc.IntegrityError:
            self.session.rollback()
            raise exceptions.SAMLConfigParameterException(
                tenant_uuid, 'Integrity error on update', '500'
            )

    def delete(self, tenant_uuid) -> None:
        filter_ = SAMLConfig.tenant_uuid == str(tenant_uuid)
        self.session.query(SAMLConfig).filter(filter_).delete(synchronize_session=False)
        self.session.flush()

    def exists(self, tenant_uuid):
        filter_ = SAMLConfig.tenant_uuid == str(tenant_uuid)
        return self.session.query(SAMLConfig).filter(filter_).count() > 0
