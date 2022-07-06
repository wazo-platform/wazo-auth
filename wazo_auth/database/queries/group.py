# Copyright 2017-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import re
import random
import string

from sqlalchemy import and_, exc, text
from .base import BaseDAO, PaginatorMixin
from ..models import Email, Group, GroupPolicy, Policy, User, UserGroup
from . import filters
from ... import exceptions

MAX_SLUG_LEN = 80
SLUG_LEN = 3


class GroupDAO(filters.FilterMixin, PaginatorMixin, BaseDAO):

    constraint_to_column_map = {'auth_group_name_key': 'name'}
    search_filter = filters.group_search_filter
    strict_filter = filters.group_strict_filter
    column_map = {'name': Group.name, 'uuid': Group.uuid}

    def add_policy(self, group_uuid, policy_uuid):
        group_policy = GroupPolicy(
            policy_uuid=str(policy_uuid), group_uuid=str(group_uuid)
        )
        self.session.begin_nested()
        self.session.add(group_policy)
        try:
            self.session.commit()
        except exc.IntegrityError as e:
            self.session.rollback()
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                # This association already exists.
                return
            if e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                constraint = e.orig.diag.constraint_name
                if constraint == 'auth_group_policy_group_uuid_fkey':
                    raise exceptions.UnknownGroupException(group_uuid)
                elif constraint == 'auth_group_policy_policy_uuid_fkey':
                    raise exceptions.UnknownPolicyException(policy_uuid)
            raise

    def add_user(self, group_uuid, user_uuid):
        user_group = UserGroup(user_uuid=str(user_uuid), group_uuid=str(group_uuid))
        self.session.begin_nested()
        self.session.add(user_group)
        try:
            self.session.commit()
        except exc.IntegrityError as e:
            self.session.rollback()
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                # This association already exists.
                return
            if e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                constraint = e.orig.diag.constraint_name
                if constraint == 'auth_user_group_group_uuid_fkey':
                    raise exceptions.UnknownGroupException(group_uuid)
                elif constraint == 'auth_user_group_user_uuid_fkey':
                    raise exceptions.UnknownUserException(user_uuid)
            raise

    def count(
        self,
        tenant_uuids=None,
        filtered=None,
        policy_uuid=None,
        policy_slug=None,
        **kwargs,
    ):
        filter_ = text('true')

        if tenant_uuids is not None:
            if not tenant_uuids:
                return 0
            filter_ = and_(filter_, Group.tenant_uuid.in_(tenant_uuids))

        if filtered is not False:
            strict_filter = self.new_strict_filter(**kwargs)
            search_filter = self.new_search_filter(**kwargs)
            filter_ = and_(filter_, strict_filter, search_filter)

            if policy_uuid:
                filter_ = and_(filter_, self._policy_uuid_filter(policy_uuid))

            if policy_slug:
                filter_ = and_(filter_, self._policy_slug_filter(policy_slug))

        return self.session.query(Group).filter(filter_).count()

    def count_policies(self, group_uuid, filtered=None, **kwargs):
        if filtered is not False:
            strict_filter = filters.policy_strict_filter.new_filter(**kwargs)
            search_filter = filters.policy_search_filter.new_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, GroupPolicy.group_uuid == str(group_uuid))

        return self.session.query(GroupPolicy).join(Policy).filter(filter_).count()

    def count_users(self, group_uuid, filtered=False, **kwargs):
        filter_ = UserGroup.group_uuid == str(group_uuid)

        if filtered:
            strict_filter = filters.user_strict_filter.new_filter(**kwargs)
            search_filter = filters.user_search_filter.new_filter(**kwargs)
            filter_ = and_(filter_, strict_filter, search_filter)

        return (
            self.session.query(UserGroup)
            .join(User)
            .outerjoin(Email)
            .filter(filter_)
            .count()
        )

    def create(self, name, slug, tenant_uuid, system_managed, **ignored):
        if not slug:
            slug = self._generate_slug(name)

        group = Group(
            name=name, slug=slug, tenant_uuid=tenant_uuid, system_managed=system_managed
        )
        self.session.add(group)
        try:
            self.session.flush()
        except exc.IntegrityError as e:
            self.session.rollback()
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                raise exceptions.DuplicateGroupException(name)
            raise
        return group.uuid

    def delete(self, uuid, tenant_uuids=None):
        filter_ = Group.uuid == str(uuid)
        if tenant_uuids is not None:
            if not tenant_uuids:
                raise exceptions.UnknownGroupException(uuid)

            filter_ = and_(filter_, Group.tenant_uuid.in_(tenant_uuids))

        nb_deleted = (
            self.session.query(Group).filter(filter_).delete(synchronize_session=False)
        )

        self.session.flush()
        if not nb_deleted:
            raise exceptions.UnknownGroupException(uuid)

    def exists(self, uuid, tenant_uuids=None):
        return self.count(uuid=uuid, tenant_uuids=tenant_uuids) > 0

    def find_by(self, **kwargs):
        filter_ = self.new_strict_filter(**kwargs)
        query = self.session.query(Group).filter(filter_)
        group = query.first()
        return group

    def list_(self, tenant_uuids=None, policy_uuid=None, policy_slug=None, **kwargs):
        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self.new_strict_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)
        if tenant_uuids is not None:
            if not tenant_uuids:
                return []

            filter_ = and_(filter_, Group.tenant_uuid.in_(tenant_uuids))

        if policy_uuid:
            filter_ = and_(filter_, self._policy_uuid_filter(policy_uuid))

        if policy_slug:
            filter_ = and_(filter_, self._policy_slug_filter(policy_slug))

        query = (
            self.session.query(Group)
            .outerjoin(UserGroup)
            .filter(filter_)
            .group_by(Group)
        )
        query = self._paginator.update_query(query, **kwargs)

        return [
            {
                'uuid': group.uuid,
                'name': group.name,
                'slug': group.slug,
                'tenant_uuid': group.tenant_uuid,
                'system_managed': group.system_managed,
                'read_only': group.system_managed,
            }
            for group in query.all()
        ]

    def update(self, group_uuid, name, tenant_uuids=None, **body):
        filter_ = Group.uuid == str(group_uuid)
        if tenant_uuids is not None:
            filter_ = and_(filter_, Group.tenant_uuid.in_(tenant_uuids))

        new_group = {
            'name': name,
        }
        new_group.update(body)
        try:
            affected_rows = (
                self.session.query(Group)
                .filter(filter_)
                .update(new_group, synchronize_session='fetch')
            )
            if not affected_rows:
                raise exceptions.UnknownGroupException(group_uuid)

            self.session.flush()
        except exc.IntegrityError as e:
            self.session.rollback()
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                raise exceptions.DuplicateGroupException(name)
            raise

        return {'uuid': str(group_uuid), **new_group}

    def remove_policy(self, group_uuid, policy_uuid):
        filter_ = and_(
            GroupPolicy.policy_uuid == str(policy_uuid),
            GroupPolicy.group_uuid == str(group_uuid),
        )

        result = self.session.query(GroupPolicy).filter(filter_).delete()
        self.session.flush()
        return result

    def remove_user(self, group_uuid, user_uuid):
        filter_ = and_(
            UserGroup.user_uuid == str(user_uuid),
            UserGroup.group_uuid == str(group_uuid),
        )

        result = self.session.query(UserGroup).filter(filter_).delete()
        self.session.flush()
        return result

    def is_system_managed(self, uuid, tenant_uuids=None):
        filter_ = Group.uuid == str(uuid)
        if tenant_uuids is not None:
            if not tenant_uuids:
                raise exceptions.UnknownGroupException(uuid)

            filter_ = and_(filter_, Group.tenant_uuid.in_(tenant_uuids))

        result = self.session.query(Group).filter(filter_).first()

        if not result:
            raise exceptions.UnknownGroupException(uuid)

        return result.system_managed

    def get_all_users_group(self, tenant_uuid):
        name = f'wazo-all-users-tenant-{tenant_uuid}'
        query = (
            self.session.query(Group)
            .filter(Group.name == name)
            .filter(Group.tenant_uuid == tenant_uuid)
        )
        return query.first()

    def _policy_uuid_filter(self, policy_uuid):
        return self._policy_filter(Policy.uuid == policy_uuid)

    def _policy_slug_filter(self, policy_slug):
        return self._policy_filter(Policy.slug == policy_slug)

    def _policy_filter(self, filter_):
        group_policy_subquery = (
            self.session.query(Group.uuid)
            .join(GroupPolicy, Group.uuid == GroupPolicy.group_uuid)
            .join(Policy, GroupPolicy.policy_uuid == Policy.uuid)
            .filter(filter_)
            .subquery()
        )
        return Group.uuid.in_(group_policy_subquery)

    def _generate_slug(self, name):
        if name:
            slug = _slug_from_name(name)
            if not self._slug_exist(slug):
                return slug

        while True:
            slug = _generate_random_name(SLUG_LEN)
            if not self._slug_exist(slug):
                return slug

    def _slug_exist(self, slug):
        return self.session.query(Policy.slug).filter(Policy.slug == slug).count() > 0


def _slug_from_name(name):
    return re.sub(r'[^a-zA-Z0-9_-]', '', name)[:MAX_SLUG_LEN]


def _generate_random_name(length):
    choices = string.ascii_lowercase + string.digits
    return ''.join(random.choice(choices) for _ in range(length))
