# Copyright 2016-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import json
from sqlalchemy import and_, exc
from .base import BaseDAO, PaginatorMixin
from . import filters
from ..models import (
    ExternalAuthConfig,
    ExternalAuthType,
    Tenant,
    User,
    UserExternalAuth,
)
from ... import exceptions


class ExternalAuthDAO(filters.FilterMixin, PaginatorMixin, BaseDAO):

    search_filter = filters.external_auth_search_filter
    strict_filter = filters.external_auth_strict_filter
    column_map = {'type': ExternalAuthType.name}

    def count(self, user_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        base_filter = ExternalAuthType.enabled.is_(True)

        if filtered is False:
            filter_ = base_filter
        else:
            search_filter = self.new_search_filter(**kwargs)
            strict_filter = self.new_strict_filter(**kwargs)
            filter_ = and_(base_filter, search_filter, strict_filter)

        return self.session.query(ExternalAuthType).filter(filter_).count()

    def create(self, user_uuid, auth_type, data):
        serialized_data = json.dumps(data)
        external_type = self._find_or_create_type(auth_type)
        user_external_auth = UserExternalAuth(
            user_uuid=str(user_uuid),
            external_auth_type_uuid=external_type.uuid,
            data=serialized_data,
        )
        self.session.add(user_external_auth)
        try:
            self.session.flush()
        except exc.IntegrityError as e:
            if e.orig.pgcode in (
                self._UNIQUE_CONSTRAINT_CODE,
                self._FKEY_CONSTRAINT_CODE,
            ):
                constraint = e.orig.diag.constraint_name
                if constraint == 'auth_external_user_type_auth_constraint':
                    raise exceptions.ExternalAuthAlreadyExists(auth_type)
                elif constraint == 'auth_user_external_auth_user_uuid_fkey':
                    raise exceptions.UnknownUserException(user_uuid)
            raise
        return data

    def create_config(self, auth_type, data, tenant_uuid):
        self._assert_tenant_exists(tenant_uuid)
        data = json.dumps(data)
        external_type = self._find_or_create_type(auth_type)
        external_auth_config = ExternalAuthConfig(
            tenant_uuid=tenant_uuid, type_uuid=external_type.uuid, data=data,
        )
        self.session.add(external_auth_config)
        try:
            self.session.flush()
        except exc.IntegrityError as e:
            if e.orig.pgcode in (self._UNIQUE_CONSTRAINT_CODE):
                constraint = e.orig.diag.constraint_name
                if constraint == 'auth_external_auth_config_pkey':
                    raise exceptions.ExternalAuthConfigAlreadyExists(auth_type)
            raise
        return data

    def delete(self, user_uuid, auth_type):
        type_ = self._find_type(auth_type)
        filter_ = and_(
            UserExternalAuth.user_uuid == str(user_uuid),
            UserExternalAuth.external_auth_type_uuid == type_.uuid,
        )
        nb_deleted = self.session.query(UserExternalAuth).filter(filter_).delete()
        self.session.flush()
        if nb_deleted:
            return

        self._assert_user_exists(user_uuid)
        raise exceptions.UnknownExternalAuthException(auth_type)

    def delete_config(self, auth_type, tenant_uuid):
        type_ = self._find_type(auth_type)
        filter_ = and_(
            ExternalAuthConfig.type_uuid == type_.uuid,
            ExternalAuthConfig.tenant_uuid == tenant_uuid,
        )
        nb_deleted = self.session.query(ExternalAuthConfig).filter(filter_).delete()
        self.session.flush()
        if nb_deleted:
            return

        raise exceptions.UnknownExternalAuthConfigException(auth_type)

    def enable_all(self, auth_types):
        query = self.session.query(ExternalAuthType.name, ExternalAuthType.enabled)
        all_types = {r.name: r.enabled for r in query.all()}

        for type_ in auth_types:
            if type_ in all_types:
                continue
            self.session.add(ExternalAuthType(name=type_, enabled=True))

        for type_, enabled in all_types.items():
            if type_ in auth_types and enabled:
                continue

            if type_ not in auth_types and not enabled:
                continue

            filter_ = ExternalAuthType.name == type_
            value = type_ in auth_types and not enabled
            self.session.query(ExternalAuthType).filter(filter_).update(
                {'enabled': value}
            )
        self.session.flush()

    def get(self, user_uuid, auth_type):
        filter_ = and_(
            UserExternalAuth.user_uuid == str(user_uuid),
            ExternalAuthType.name == auth_type,
        )

        data = (
            self.session.query(UserExternalAuth.data)
            .join(ExternalAuthType)
            .filter(filter_)
            .first()
        )

        if data:
            return json.loads(data.data)

        self._assert_type_exists(auth_type)
        self._assert_user_exists(user_uuid)
        raise exceptions.UnknownExternalAuthException(auth_type)

    def get_config(self, auth_type, tenant_uuid):
        try:
            external_auth_type = self._find_type(auth_type)
        except exceptions.UnknownExternalAuthTypeException:
            raise exceptions.ExternalAuthConfigNotFound(auth_type)

        result = (
            self.session.query(ExternalAuthConfig.data)
            .join(ExternalAuthType)
            .filter(
                ExternalAuthType.name == external_auth_type.name,
                ExternalAuthConfig.tenant_uuid == tenant_uuid,
            )
            .first()
        )

        if result:
            return json.loads(result.data)

        raise exceptions.UnknownExternalAuthConfigException(auth_type)

    def list_(self, user_uuid, **kwargs):
        base_filter = ExternalAuthType.enabled.is_(True)
        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self.new_strict_filter(**kwargs)
        filter_ = and_(base_filter, search_filter, strict_filter)

        result = []

        query = self.session.query(ExternalAuthType).filter(filter_)
        query = self._paginator.update_query(query, **kwargs)
        result = [{'type': r.name, 'data': {}, 'enabled': False} for r in query.all()]

        filter_ = and_(filter_, UserExternalAuth.user_uuid == str(user_uuid))
        query = (
            self.session.query(ExternalAuthType.name, UserExternalAuth.data)
            .select_from(UserExternalAuth)
            .join(ExternalAuthType)
            .filter(filter_)
        )
        for type_, data in query.all():
            for row in result:
                if row['type'] != type_:
                    continue
                row.update({'enabled': True, 'data': json.loads(data)})

        return result

    def update(self, user_uuid, auth_type, data):
        self.delete(user_uuid, auth_type)
        result = self.create(user_uuid, auth_type, data)
        self.session.flush()
        return result

    def update_config(self, auth_type, data, tenant_uuid):
        self.delete_config(auth_type, tenant_uuid)
        result = self.create_config(auth_type, data, tenant_uuid)
        self.session.flush()
        return result

    def _assert_tenant_exists(self, tenant_uuid):
        if (
            self.session.query(Tenant).filter(Tenant.uuid == str(tenant_uuid)).count()
            == 0
        ):
            raise exceptions.TenantParamException(tenant_uuid)

    def _assert_type_exists(self, auth_type):
        self._find_type(auth_type)

    def _assert_user_exists(self, user_uuid):
        if self.session.query(User).filter(User.uuid == str(user_uuid)).count() == 0:
            raise exceptions.UnknownUserException(user_uuid)

    def _find_type(self, auth_type):
        type_ = (
            self.session.query(ExternalAuthType)
            .filter(ExternalAuthType.name == auth_type)
            .first()
        )
        if type_:
            return type_
        raise exceptions.UnknownExternalAuthTypeException(auth_type)

    def _find_or_create_type(self, auth_type):
        try:
            type_ = self._find_type(auth_type)
        except exceptions.UnknownExternalAuthTypeException:
            type_ = ExternalAuthType(name=auth_type)
            self.session.add(type_)
        self.session.flush()
        return type_
