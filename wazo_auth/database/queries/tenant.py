# Copyright 2017-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import and_, exc, text
from wazo_auth import schemas
from .base import BaseDAO, PaginatorMixin
from ..models import Address, Policy, Tenant, User
from . import filters
from ... import exceptions


class TenantDAO(filters.FilterMixin, PaginatorMixin, BaseDAO):

    constraint_to_column_map = {'auth_tenant_name_key': 'name'}
    search_filter = filters.tenant_search_filter
    strict_filter = filters.tenant_strict_filter
    column_map = {'name': Tenant.name}

    def exists(self, tenant_uuid):
        return self.count([str(tenant_uuid)]) > 0

    def count(self, tenant_uuids, **kwargs):
        filter_ = Tenant.uuid.in_(tenant_uuids)

        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = self.new_strict_filter(**kwargs)
            search_filter = self.new_search_filter(**kwargs)
            filter_ = and_(filter_, strict_filter, search_filter)

        return self.session.query(Tenant).filter(filter_).count()

    def count_policies(self, tenant_uuid, filtered=False, **kwargs):
        filter_ = Policy.tenant_uuid == str(tenant_uuid)

        if filtered is not False:
            strict_filter = filters.policy_strict_filter.new_filter(**kwargs)
            search_filter = filters.policy_search_filter.new_filter(**kwargs)
            filter_ = and_(filter_, strict_filter, search_filter)

        return self.session.query(Policy.uuid).filter(filter_).count()

    def count_users(self, tenant_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        filter_ = User.tenant_uuid == str(tenant_uuid)
        if filtered is not False:
            strict_filter = filters.user_strict_filter.new_filter(**kwargs)
            search_filter = filters.user_search_filter.new_filter(**kwargs)
            filter_ = and_(filter_, strict_filter, search_filter)

        return self.session.query(User).filter(filter_).count()

    def create(self, **kwargs):
        parent_uuid = kwargs.get('parent_uuid')
        uuid_ = kwargs.get('uuid')

        if uuid_ and parent_uuid and str(uuid_) == str(parent_uuid):
            if self.find_top_tenant():
                raise exceptions.MasterTenantConflictException()

        if not parent_uuid:
            kwargs['parent_uuid'] = self.find_top_tenant()

        tenant = Tenant(
            name=kwargs['name'],
            phone=kwargs['phone'],
            contact_uuid=kwargs['contact_uuid'],
            address_id=kwargs['address_id'],
            parent_uuid=str(kwargs['parent_uuid']),
        )
        if uuid_:
            tenant.uuid = str(uuid_)

        self.session.add(tenant)
        try:
            self.session.flush()
        except exc.IntegrityError as e:
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                column = self.constraint_to_column_map.get(e.orig.diag.constraint_name)
                value = locals().get(column)
                if column:
                    raise exceptions.ConflictException('tenants', column, value)
            elif e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                constraint = e.orig.diag.constraint_name
                if constraint == 'auth_tenant_contact_uuid_fkey':
                    raise exceptions.UnknownUserException(kwargs['contact_uuid'])
            raise
        return tenant.uuid

    def find_top_tenant(self):
        return (
            self.session.query(Tenant)
            .filter(Tenant.uuid == Tenant.parent_uuid)
            .first()
            .uuid
        )

    def delete(self, uuid):
        nb_deleted = (
            self.session.query(Tenant).filter(Tenant.uuid == str(uuid)).delete()
        )
        self.session.flush()
        if not nb_deleted:
            if not self.list_(uuid=uuid):
                raise exceptions.UnknownTenantException(uuid)
            else:
                raise exceptions.UnknownUserException(uuid)

    def get_address_id(self, tenant_uuid):
        return (
            self.session.query(Tenant.address_id)
            .filter(Tenant.uuid == str(tenant_uuid))
            .scalar()
        )

    def list_visible_tenants(self, scoping_tenant_uuid=None):
        query = self._tenant_query(scoping_tenant_uuid)
        return query.all()

    def list_(self, **kwargs):
        schema = schemas.TenantSchema()
        filter_ = text('true')

        tenant_uuids = kwargs.get('tenant_uuids')
        if tenant_uuids is not None:
            filter_ = Tenant.uuid.in_(tenant_uuids)

        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self.new_strict_filter(**kwargs)
        filter_ = and_(filter_, strict_filter, search_filter)

        query = (
            self.session.query(Tenant, Address)
            .outerjoin(Address)
            .filter(filter_)
            .group_by(Tenant, Address)
        )
        query = self._paginator.update_query(query, **kwargs)

        def to_dict(tenant, address):
            tenant.address = address
            return schema.dump(tenant)

        return [to_dict(*row) for row in query.all()]

    def update(self, tenant_uuid, **kwargs):
        filter_ = Tenant.uuid == str(tenant_uuid)
        values = {
            'name': kwargs.get('name'),
            'contact_uuid': kwargs.get('contact_uuid'),
            'phone': kwargs.get('phone'),
            'address_id': kwargs.get('address_id'),
        }

        try:
            self.session.query(Tenant).filter(filter_).update(values)
            self.session.flush()
        except exc.IntegrityError as e:
            if e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                constraint = e.orig.diag.constraint_name
                if constraint == 'auth_tenant_contact_uuid_fkey':
                    raise exceptions.UnknownUserException(kwargs['contact_uuid'])
            raise

    def _tenant_query(self, scoping_tenant_uuid):
        top_tenant_uuid = self.find_top_tenant()
        if scoping_tenant_uuid is None:
            scoping_tenant_uuid = top_tenant_uuid

        if scoping_tenant_uuid == top_tenant_uuid:
            return self.session.query(Tenant)

        included_tenants = (
            self.session.query(Tenant.uuid, Tenant.parent_uuid)
            .filter(Tenant.uuid == str(scoping_tenant_uuid))
            .cte(recursive=True)
        )
        included_tenants = included_tenants.union_all(
            self.session.query(Tenant.uuid, Tenant.parent_uuid).filter(
                and_(
                    Tenant.parent_uuid == included_tenants.c.uuid,
                    Tenant.uuid != Tenant.parent_uuid,
                )
            )
        )
        return (
            self.session.query(Tenant)
            .select_from(included_tenants)
            .join(Tenant, Tenant.uuid == included_tenants.c.uuid)
        )
