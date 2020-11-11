# Copyright 2017-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import and_, distinct, exc, func, text
from .base import BaseDAO, PaginatorMixin
from . import filters
from ..models import (
    ACLTemplate,
    ACLTemplatePolicy,
    GroupPolicy,
    Policy,
    Tenant,
    UserPolicy,
)
from ... import exceptions


class PolicyDAO(filters.FilterMixin, PaginatorMixin, BaseDAO):

    search_filter = filters.policy_search_filter
    strict_filter = filters.policy_strict_filter
    column_map = {
        'name': Policy.name,
        'description': Policy.description,
        'uuid': Policy.uuid,
    }

    def associate_policy_access(self, policy_uuid, access):
        self._associate_acl(policy_uuid, [access])
        try:
            self.session.flush()
        except exc.IntegrityError as e:
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                raise exceptions.DuplicateTemplateException(access)
            if e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                constraint = e.orig.diag.constraint_name
                if constraint == 'auth_policy_template_policy_uuid_fkey':
                    raise exceptions.UnknownPolicyException(policy_uuid)
            raise

    def dissociate_policy_access(self, policy_uuid, access):
        filter_ = and_(
            ACLTemplate.template == access,
            ACLTemplatePolicy.policy_uuid == policy_uuid,
        )

        access_id = (
            self.session.query(ACLTemplate.id_)
            .join(ACLTemplatePolicy)
            .filter(filter_)
            .first()
        )
        if not access_id:
            return 0

        filter_ = and_(
            ACLTemplatePolicy.policy_uuid == policy_uuid,
            ACLTemplatePolicy.template_id == access_id,
        )
        result = self.session.query(ACLTemplatePolicy).filter(filter_).delete()
        self.session.flush()
        return result

    def count_tenants(self, policy_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = filters.tenant_strict_filter.new_filter(**kwargs)
            search_filter = filters.tenant_search_filter.new_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        return self.session.query(Tenant).filter(filter_).count()

    def count(self, search, tenant_uuids=None, **ignored):
        filter_ = self.new_search_filter(search=search)

        if tenant_uuids is not None:
            filter_ = and_(filter_, Policy.tenant_uuid.in_(tenant_uuids))

        return self.session.query(Policy).filter(filter_).count()

    def create(self, name, description, acl, config_managed, tenant_uuid):
        policy = Policy(
            name=name,
            description=description,
            config_managed=config_managed,
            tenant_uuid=tenant_uuid,
        )
        self.session.add(policy)
        try:
            self.session.flush()
        except exc.IntegrityError as e:
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                raise exceptions.DuplicatePolicyException(name)
            raise
        self._associate_acl(policy.uuid, acl)
        self.session.flush()
        return policy.uuid

    def delete(self, policy_uuid, tenant_uuids):
        filter_ = Policy.uuid == policy_uuid
        if tenant_uuids is not None:
            filter_ = and_(filter_, Policy.tenant_uuid.in_(tenant_uuids))

        nb_deleted = (
            self.session.query(Policy).filter(filter_).delete(synchronize_session=False)
        )
        self.session.flush()
        if not nb_deleted:
            raise exceptions.UnknownPolicyException(policy_uuid)

    def exists(self, uuid, tenant_uuids=None):
        return self._policy_exists(uuid, tenant_uuids)

    def get(self, tenant_uuids=None, **kwargs):
        strict_filter = self.new_strict_filter(**kwargs)
        search_filter = self.new_search_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)

        if tenant_uuids is not None:
            filter_ = and_(filter_, Policy.tenant_uuid.in_(tenant_uuids))

        query = (
            self.session.query(
                Policy.uuid,
                Policy.name,
                Policy.description,
                Policy.config_managed,
                Policy.tenant_uuid,
                func.array_agg(distinct(ACLTemplate.template)).label('acl'),
            )
            .outerjoin(ACLTemplatePolicy)
            .outerjoin(ACLTemplate)
            .outerjoin(UserPolicy)
            .outerjoin(GroupPolicy)
            .filter(filter_)
            .group_by(Policy.uuid, Policy.name, Policy.description)
        )
        query = self._paginator.update_query(query, **kwargs)

        policies = []
        for policy in query.all():
            if policy.acl == [None]:
                acl = []
            else:
                acl = policy.acl

            body = {
                'uuid': policy.uuid,
                'name': policy.name,
                'description': policy.description,
                'acl': acl,
                'tenant_uuid': policy.tenant_uuid,
                'config_managed': policy.config_managed,
            }
            policies.append(body)

        return policies

    def list_(self, **kwargs):
        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self.new_strict_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)

        query = self.session.query(Policy).filter(filter_).group_by(Policy)
        query = self._paginator.update_query(query, **kwargs)

        return [
            {
                'uuid': policy.uuid,
                'name': policy.name,
                'tenant_uuid': policy.tenant_uuid,
            }
            for policy in query.all()
        ]

    def update(
        self,
        policy_uuid,
        name,
        description,
        acl,
        config_managed,
        tenant_uuids=None,
    ):
        filter_ = Policy.uuid == policy_uuid
        if tenant_uuids is not None:
            filter_ = and_(filter_, Policy.tenant_uuid.in_(tenant_uuids))

        body = {
            'name': name,
            'description': description,
            'config_managed': config_managed,
        }
        affected_rows = (
            self.session.query(Policy)
            .filter(filter_)
            .update(body, synchronize_session='fetch')
        )
        if not affected_rows:
            raise exceptions.UnknownPolicyException(policy_uuid)

        try:
            self.session.flush()
        except exc.IntegrityError as e:
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                raise exceptions.DuplicatePolicyException(name)
            raise

        self._dissociate_all_acl(policy_uuid)
        self._associate_acl(policy_uuid, acl)
        self.session.flush()

    def _associate_acl(self, policy_uuid, acl):
        ids = self._create_or_find_acl(acl)
        access_policies = [
            ACLTemplatePolicy(policy_uuid=policy_uuid, template_id=id_) for id_ in ids
        ]
        self.session.add_all(access_policies)

    def _create_or_find_acl(self, acl):
        if not acl:
            return []

        tpl = (
            self.session.query(ACLTemplate).filter(ACLTemplate.template.in_(acl)).all()
        )
        existing = {t.template: t.id_ for t in tpl}
        for access in acl:
            if access in existing:
                continue
            id_ = self._insert_access(access)
            existing[access] = id_
        result = existing.values()
        self.session.flush()
        return result

    def _dissociate_all_acl(self, policy_uuid):
        filter_ = ACLTemplatePolicy.policy_uuid == policy_uuid
        self.session.query(ACLTemplatePolicy).filter(filter_).delete()
        self.session.flush()

    def _insert_access(self, access):
        tpl = ACLTemplate(template=access)
        self.session.add(tpl)
        self.session.flush()
        return tpl.id_

    def _policy_exists(self, policy_uuid, tenant_uuids=None):
        filter_ = Policy.uuid == str(policy_uuid)

        if tenant_uuids is not None:
            if not tenant_uuids:
                return False

            filter_ = and_(filter_, Policy.tenant_uuid.in_(tenant_uuids))

        result = self.session.query(Policy).filter(filter_).count() > 0
        self.session.flush()
        return result
