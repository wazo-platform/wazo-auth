# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

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

    def associate_policy_template(self, policy_uuid, acl_template):
        with self.new_session() as s:
            self._associate_acl_templates(s, policy_uuid, [acl_template])
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    raise exceptions.DuplicateTemplateException(acl_template)
                if e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                    constraint = e.orig.diag.constraint_name
                    if constraint == 'auth_policy_template_policy_uuid_fkey':
                        raise exceptions.UnknownPolicyException(policy_uuid)
                raise

    def dissociate_policy_template(self, policy_uuid, acl_template):
        with self.new_session() as s:
            filter_ = and_(
                ACLTemplate.template == acl_template,
                ACLTemplatePolicy.policy_uuid == policy_uuid,
            )

            template_id = s.query(ACLTemplate.id_).join(ACLTemplatePolicy).filter(filter_).first()
            if not template_id:
                return 0

            filter_ = and_(
                ACLTemplatePolicy.policy_uuid == policy_uuid,
                ACLTemplatePolicy.template_id == template_id,
            )
            return s.query(ACLTemplatePolicy).filter(filter_).delete()

    def count_tenants(self, policy_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = filters.tenant_strict_filter.new_filter(**kwargs)
            search_filter = filters.tenant_search_filter.new_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        with self.new_session() as s:
            return s.query(Tenant).filter(filter_).count()

    def count(self, search, **ignored):
        filter_ = self.new_search_filter(search=search)
        with self.new_session() as s:
            return s.query(Policy).filter(filter_).count()

    def create(self, name, description, acl_templates):
        policy = Policy(name=name, description=description)
        with self.new_session() as s:
            s.add(policy)
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    raise exceptions.DuplicatePolicyException(name)
                raise
            self._associate_acl_templates(s, policy.uuid, acl_templates)
            return policy.uuid

    def delete(self, policy_uuid):
        filter_ = Policy.uuid == policy_uuid

        with self.new_session() as s:
            nb_deleted = s.query(Policy).filter(filter_).delete()

        if not nb_deleted:
            raise exceptions.UnknownPolicyException(policy_uuid)

    def exists(self, uuid):
        with self.new_session() as s:
            return self._policy_exists(s, uuid)

    def get(self, **kwargs):
        strict_filter = self.new_strict_filter(**kwargs)
        search_filter = self.new_search_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)
        with self.new_session() as s:
            query = s.query(
                Policy.uuid,
                Policy.name,
                Policy.description,
                func.array_agg(distinct(ACLTemplate.template)).label('acl_templates'),
            ).outerjoin(
                ACLTemplatePolicy,
            ).outerjoin(
                ACLTemplate,
            ).outerjoin(
                UserPolicy,
            ).outerjoin(
                GroupPolicy,
            ).filter(
                filter_,
            ).group_by(
                Policy.uuid,
                Policy.name,
                Policy.description,
            )
            query = self._paginator.update_query(query, **kwargs)

            policies = []
            for policy in query.all():
                if policy.acl_templates == [None]:
                    acl_templates = []
                else:
                    acl_templates = policy.acl_templates

                body = {
                    'uuid': policy.uuid,
                    'name': policy.name,
                    'description': policy.description,
                    'acl_templates': acl_templates,
                }
                policies.append(body)

        return policies

    def list_(self, **kwargs):
        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self.new_strict_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)

        with self.new_session() as s:
            query = s.query(
                Policy.uuid,
                Policy.name,
            ).filter(filter_).group_by(Policy)
            query = self._paginator.update_query(query, **kwargs)

            return [{'uuid': uuid, 'name': name} for uuid, name in query.all()]

    def update(self, policy_uuid, name, description, acl_templates):
        with self.new_session() as s:
            filter_ = Policy.uuid == policy_uuid
            body = {'name': name, 'description': description}
            affected_rows = s.query(Policy).filter(filter_).update(body)
            if not affected_rows:
                raise exceptions.UnknownPolicyException(policy_uuid)

            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    raise exceptions.DuplicatePolicyException(name)
                raise

            self._dissociate_all_acl_templates(s, policy_uuid)
            self._associate_acl_templates(s, policy_uuid, acl_templates)

    def _associate_acl_templates(self, session, policy_uuid, acl_templates):
        ids = self._create_or_find_acl_templates(session, acl_templates)
        template_policies = [ACLTemplatePolicy(policy_uuid=policy_uuid, template_id=id_) for id_ in ids]
        session.add_all(template_policies)

    def _create_or_find_acl_templates(self, s, acl_templates):
        if not acl_templates:
            return []

        tpl = s.query(ACLTemplate).filter(ACLTemplate.template.in_(acl_templates)).all()
        existing = {t.template: t.id_ for t in tpl}
        for template in acl_templates:
            if template in existing:
                continue
            id_ = self._insert_acl_template(s, template)
            existing[template] = id_
        return existing.values()

    def _dissociate_all_acl_templates(self, s, policy_uuid):
        filter_ = ACLTemplatePolicy.policy_uuid == policy_uuid
        s.query(ACLTemplatePolicy).filter(filter_).delete()

    def _insert_acl_template(self, s, template):
        tpl = ACLTemplate(template=template)
        s.add(tpl)
        s.commit()
        return tpl.id_

    def _policy_exists(self, s, policy_uuid):
        policy_count = s.query(Policy).filter(Policy.uuid == str(policy_uuid)).count()
        return policy_count > 0
