# Copyright 2017-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import and_, exc, text
from sqlalchemy.orm import joinedload

from wazo_auth import schemas

from ... import exceptions
from ...slug import TenantSlug
from ..models import Address, Tenant, User
from . import filters
from .base import BaseDAO, PaginatorMixin


class TenantDAO(filters.FilterMixin, PaginatorMixin, BaseDAO):
    constraint_to_column_map = {
        'auth_tenant_name_key': 'name',
        'auth_tenant_slug_key': 'slug',
    }
    search_filter = filters.tenant_search_filter
    strict_filter = filters.tenant_strict_filter
    column_map = {'name': Tenant.name, 'slug': Tenant.slug}

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
        domain_names = kwargs.get('domain_names', [])

        if uuid_ and parent_uuid and str(uuid_) == str(parent_uuid):
            if self.find_top_tenant():
                raise exceptions.MasterTenantConflictException()

        if not parent_uuid:
            kwargs['parent_uuid'] = self.find_top_tenant()

        slug = kwargs['slug']
        if not slug:
            slug = self._generate_slug(kwargs['name'])

        tenant = Tenant(
            name=kwargs['name'],
            slug=slug,
            phone=kwargs['phone'],
            contact_uuid=kwargs['contact_uuid'],
            parent_uuid=str(kwargs['parent_uuid']),
        )
        if uuid_:
            tenant.uuid = str(uuid_)

        tenant.domain_names = domain_names

        self.session.add(tenant)
        try:
            self.session.flush()
        except exc.IntegrityError as e:
            self.session.rollback()
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                constraint = e.orig.diag.constraint_name
                if constraint == 'auth_tenant_domain_name_key':
                    raise exceptions.DomainAlreadyExistException(domain_names)
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
        tenant = self.session.query(Tenant).get(str(uuid))
        if not tenant:
            raise exceptions.UnknownTenantException(uuid)

        query = self.session.query(Tenant).filter(Tenant.parent_uuid == str(uuid))
        children_count = query.count()
        if children_count > 0:
            raise exceptions.UnauthorizedTenantwithChildrenDelete(uuid)
        else:
            self.session.delete(tenant)

        self.session.flush()
        # NOTE: A lot of resources have been delete by cascade
        self.session.expire_all()

    def get_address_id(self, tenant_uuid):
        return (
            self.session.query(Address.id_)
            .filter(Address.tenant_uuid == str(tenant_uuid))
            .scalar()
        )

    def list_visible_tenants(self, scoping_tenant_uuid=None):
        query = self._tenant_query(scoping_tenant_uuid)
        return query.all()

    def list_(self, **kwargs):
        schema = schemas.TenantFullSchema()
        filter_ = text('true')

        tenant_uuids = kwargs.get('tenant_uuids')
        if tenant_uuids is not None:
            filter_ = Tenant.uuid.in_(tenant_uuids)

        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self.new_strict_filter(**kwargs)
        filter_ = and_(filter_, strict_filter, search_filter)

        query = (
            self.session.query(Tenant)
            .filter(filter_)
            .options(joinedload('address'))
            .options(joinedload('domains'))
        )
        query = self._paginator.update_query(query, **kwargs)

        return [schema.dump(row) for row in query.all()]

    def update(
        self,
        tenant_uuid,
        name=None,
        phone=None,
        domain_names=None,
        contact_uuid=None,
        **kwargs
    ):
        try:
            tenant = self.session.query(Tenant).get(str(tenant_uuid))
            tenant.domain_names = domain_names or []
            tenant.contact_uuid = contact_uuid
            tenant.phone = phone
            tenant.name = name
            self.session.flush()
        except exc.IntegrityError as e:
            self.session.rollback()
            if e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                constraint = e.orig.diag.constraint_name
                if constraint == 'auth_tenant_contact_uuid_fkey':
                    raise exceptions.UnknownUserException(contact_uuid)
            elif e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                constraint = e.orig.diag.constraint_name
                if constraint == 'auth_tenant_domain_name_key':
                    raise exceptions.DomainAlreadyExistException(domain_names)
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

    def _generate_slug(self, name):
        if name:
            slug = TenantSlug.from_name(name)
            if not self._slug_exist(slug):
                return slug

        while True:
            slug = TenantSlug.random(length=3)
            if not self._slug_exist(slug):
                return slug

    def _slug_exist(self, slug):
        return self.session.query(Tenant.slug).filter(Tenant.slug == slug).count() > 0
