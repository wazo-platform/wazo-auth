# Copyright 2017-2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import and_, exc, text
from sqlalchemy.orm import joinedload

from wazo_auth.plugins.http.tenants import schemas

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
        return bool(
            self.session.query(Tenant).filter(Tenant.uuid == tenant_uuid).first()
        )

    def count(self, top_tenant_uuid, scoping_tenant_uuid=None, **kwargs):
        query = self._tenant_query(top_tenant_uuid, scoping_tenant_uuid)
        filter_ = text('true')
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = self.new_strict_filter(**kwargs)
            search_filter = self.new_search_filter(**kwargs)
            filter_ = and_(filter_, strict_filter, search_filter)

        return query.filter(filter_).count()

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
            default_authentication_method=kwargs['default_authentication_method'],
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
        tenant = self.session.get(Tenant, str(uuid))
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

    def is_subtenant(self, child_uuid, parent_uuid):
        if parent_uuid is None or child_uuid is None:
            return False

        if parent_uuid == child_uuid:
            return True

        if not self.exists(child_uuid):
            return False

        top_tenant_uuid = self.find_top_tenant()
        if parent_uuid == top_tenant_uuid:
            return True

        parent_tenants = (
            self.session.query(Tenant.uuid)
            .filter(Tenant.uuid == str(child_uuid))
            .cte(recursive=True)
        )
        parent_tenants = parent_tenants.union_all(
            self.session.query(Tenant.parent_uuid).filter(
                and_(
                    Tenant.uuid == parent_tenants.c.uuid,
                    Tenant.uuid != parent_uuid,  # stop recursion on expected parent
                    Tenant.uuid != Tenant.parent_uuid,  # stop recursion on top tenant
                )
            )
        )

        result = (
            self.session.query(parent_tenants.c.uuid).select_from(parent_tenants).all()
        )
        uuid_chain = [row[0] for row in result]
        return child_uuid in uuid_chain and parent_uuid in uuid_chain

    def list_visible_tenants(self, scoping_tenant_uuid=None):
        top_tenant_uuid = self.find_top_tenant()
        query = self._tenant_query(top_tenant_uuid, scoping_tenant_uuid)
        return query.all()

    def get_missing_auth_methods(self, available_methods: list[str]) -> list[dict]:
        _filter = ~Tenant.default_authentication_method.in_(available_methods)
        top_tenant_uuid = self.find_top_tenant()
        query = (
            self._tenant_query(top_tenant_uuid)
            .filter(_filter)
            .with_entities(Tenant.uuid, Tenant.default_authentication_method)
        )
        return [
            {
                'uuid': tenant.uuid,
                'default_authentication_method': tenant.default_authentication_method,
            }
            for tenant in query.all()
        ]

    def list_(self, top_tenant_uuid, scoping_tenant_uuid=None, **kwargs):
        query = self._tenant_query(top_tenant_uuid, scoping_tenant_uuid)
        filter_ = text('true')

        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self.new_strict_filter(**kwargs)
        filter_ = and_(filter_, strict_filter, search_filter)

        query = (
            query.filter(filter_)
            .options(joinedload(Tenant.address))
            .options(joinedload(Tenant.domains))
        )
        query = self._paginator.update_query(query, **kwargs)

        schema = schemas.TenantFullSchema()
        return [schema.dump(row) for row in query.all()]

    def update(
        self,
        tenant_uuid,
        name=None,
        phone=None,
        domain_names=None,
        contact_uuid=None,
        default_authentication_method=None,
        **kwargs
    ):
        try:
            tenant = self.session.get(Tenant, str(tenant_uuid))
            tenant.domain_names = domain_names or []
            tenant.contact_uuid = contact_uuid
            tenant.phone = phone
            tenant.name = name
            tenant.default_authentication_method = default_authentication_method
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

    def update_parent(self, tenant_uuid, parent_uuid):
        tenant = self.session.get(Tenant, str(tenant_uuid))
        tenant.parent_uuid = parent_uuid
        self.session.flush()

    def _tenant_query(self, top_tenant_uuid, scoping_tenant_uuid=None):
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
