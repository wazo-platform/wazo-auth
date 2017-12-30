# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from sqlalchemy import and_, exc, text
from .base import BaseDAO, PaginatorMixin
from ..models import (
    Email,
    Tenant,
    TenantUser,
    User,
    UserEmail,
)
from . import filters
from ... import exceptions


class TenantDAO(filters.FilterMixin, PaginatorMixin, BaseDAO):

    constraint_to_column_map = dict(
        auth_tenant_name_key='name',
    )
    search_filter = filters.tenant_search_filter
    strict_filter = filters.tenant_strict_filter
    column_map = dict(
        name=Tenant.name,
    )

    def exists(self, tenant_uuid):
        return self.count(uuid=tenant_uuid) > 0

    def add_user(self, tenant_uuid, user_uuid):
        tenant_user = TenantUser(tenant_uuid=str(tenant_uuid), user_uuid=str(user_uuid))
        with self.new_session() as s:
            s.add(tenant_user)
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    # This association already exists.
                    s.rollback()
                    return
                if e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                    constraint = e.orig.diag.constraint_name
                    if constraint == 'auth_tenant_user_tenant_uuid_fkey':
                        raise exceptions.UnknownTenantException(tenant_uuid)
                    elif constraint == 'auth_tenant_user_user_uuid_fkey':
                        raise exceptions.UnknownUserException(user_uuid)
                raise

    def count(self, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = self.new_strict_filter(**kwargs)
            search_filter = self.new_search_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        with self.new_session() as s:
            return s.query(Tenant).filter(filter_).count()

    def count_users(self, tenant_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = filters.user_strict_filter.new_filter(**kwargs)
            search_filter = filters.user_search_filter.new_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, TenantUser.tenant_uuid == str(tenant_uuid))

        with self.new_session() as s:
            return s.query(
                TenantUser
            ).join(
                User
            ).join(
                UserEmail
            ).join(
                Email
            ).filter(filter_).count()

    def create(self, name):
        tenant = Tenant()
        if name:
            tenant.name = name
        with self.new_session() as s:
            s.add(tenant)
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    column = self.constraint_to_column_map.get(e.orig.diag.constraint_name)
                    value = locals().get(column)
                    if column:
                        raise exceptions.ConflictException('tenants', column, value)
                raise
            return tenant.uuid

    def delete(self, uuid):
        with self.new_session() as s:
            nb_deleted = s.query(Tenant).filter(Tenant.uuid == str(uuid)).delete()

        if not nb_deleted:
            if not self.list_(uuid=uuid):
                raise exceptions.UnknownTenantException(uuid)
            else:
                raise exceptions.UnknownUserException(uuid)

    def list_(self, **kwargs):
        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self.new_strict_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)

        with self.new_session() as s:
            query = s.query(
                Tenant.uuid,
                Tenant.name,
            ).outerjoin(TenantUser).filter(filter_).group_by(Tenant)
            query = self._paginator.update_query(query, **kwargs)

            return [{'uuid': uuid, 'name': name} for uuid, name in query.all()]

    def remove_user(self, tenant_uuid, user_uuid):
        filter_ = and_(
            TenantUser.user_uuid == str(user_uuid),
            TenantUser.tenant_uuid == str(tenant_uuid),
        )

        with self.new_session() as s:
            return s.query(TenantUser).filter(filter_).delete()