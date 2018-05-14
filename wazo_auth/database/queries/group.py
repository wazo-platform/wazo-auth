# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from sqlalchemy import and_, exc, text
from .base import BaseDAO, PaginatorMixin
from ..models import Email, Group, GroupPolicy, Policy, User, UserEmail, UserGroup
from . import filters
from ... import exceptions


class GroupDAO(filters.FilterMixin, PaginatorMixin, BaseDAO):

    constraint_to_column_map = {
        'auth_group_name_key': 'name',
    }
    search_filter = filters.group_search_filter
    strict_filter = filters.group_strict_filter
    column_map = {
        'name': Group.name,
        'uuid': Group.uuid,
    }

    def add_policy(self, group_uuid, policy_uuid):
        group_policy = GroupPolicy(policy_uuid=str(policy_uuid), group_uuid=str(group_uuid))
        with self.new_session() as s:
            s.add(group_policy)
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    # This association already exists.
                    s.rollback()
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
        with self.new_session() as s:
            s.add(user_group)
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    # This association already exists.
                    s.rollback()
                    return
                if e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                    constraint = e.orig.diag.constraint_name
                    if constraint == 'auth_user_group_group_uuid_fkey':
                        raise exceptions.UnknownGroupException(group_uuid)
                    elif constraint == 'auth_user_group_user_uuid_fkey':
                        raise exceptions.UnknownUserException(user_uuid)
                raise

    def count(self, tenant_uuids=None, **kwargs):
        filter_ = text('true')

        if tenant_uuids is not None:
            if not tenant_uuids:
                return 0
            filter_ = and_(filter_, Group.tenant_uuid.in_(tenant_uuids))

        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = self.new_strict_filter(**kwargs)
            search_filter = self.new_search_filter(**kwargs)
            filter_ = and_(filter_, strict_filter, search_filter)

        with self.new_session() as s:
            return s.query(Group).filter(filter_).count()

    def count_policies(self, group_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = filters.policy_strict_filter.new_filter(**kwargs)
            search_filter = filters.policy_search_filter.new_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, GroupPolicy.group_uuid == str(group_uuid))

        with self.new_session() as s:
            return s.query(GroupPolicy).join(Policy).filter(filter_).count()

    def count_users(self, group_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = filters.user_strict_filter.new_filter(**kwargs)
            search_filter = filters.user_search_filter.new_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, UserGroup.group_uuid == str(group_uuid))

        with self.new_session() as s:
            return s.query(UserGroup).join(User).join(UserEmail).join(Email).filter(filter_).count()

    def create(self, name, tenant_uuid, **ignored):
        group = Group(name=name, tenant_uuid=tenant_uuid)
        with self.new_session() as s:
            s.add(group)
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    column = self.constraint_to_column_map.get(e.orig.diag.constraint_name)
                    value = locals().get(column)
                    if column:
                        raise exceptions.ConflictException('groups', column, value)
                raise
            return group.uuid

    def delete(self, uuid, tenant_uuids=None):
        filter_ = Group.uuid == str(uuid)
        if tenant_uuids is not None:
            if not tenant_uuids:
                raise exceptions.UnknownGroupException(uuid)

            filter_ = and_(filter_, Group.tenant_uuid.in_(tenant_uuids))

        with self.new_session() as s:
            nb_deleted = s.query(Group).filter(filter_).delete(synchronize_session=False)

        if not nb_deleted:
            raise exceptions.UnknownGroupException(uuid)

    def exists(self, uuid, tenant_uuids=None):
        return self.count(uuid=uuid, tenant_uuids=tenant_uuids) > 0

    def list_(self, tenant_uuids=None, **kwargs):
        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self.new_strict_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)
        if tenant_uuids is not None:
            if not tenant_uuids:
                return []

            filter_ = and_(filter_, Group.tenant_uuid.in_(tenant_uuids))

        with self.new_session() as s:
            query = s.query(Group).outerjoin(UserGroup).filter(filter_).group_by(Group)
            query = self._paginator.update_query(query, **kwargs)

            return [{
                'uuid': group.uuid,
                'name': group.name,
                'tenant_uuid': group.tenant_uuid,
            } for group in query.all()]

    def update(self, group_uuid, **body):
        with self.new_session() as s:
            filter_ = Group.uuid == str(group_uuid)
            try:
                affected_rows = s.query(Group).filter(filter_).update(body)
                if not affected_rows:
                    raise exceptions.UnknownGroupException(group_uuid)

                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    column = self.constraint_to_column_map.get(e.orig.diag.constraint_name)
                    value = body.get(column)
                    if column:
                        raise exceptions.ConflictException('groups', column, value)
                raise

        return dict(uuid=str(group_uuid), **body)

    def remove_policy(self, group_uuid, policy_uuid):
        filter_ = and_(
            GroupPolicy.policy_uuid == str(policy_uuid),
            GroupPolicy.group_uuid == str(group_uuid),
        )

        with self.new_session() as s:
            return s.query(GroupPolicy).filter(filter_).delete()

    def remove_user(self, group_uuid, user_uuid):
        filter_ = and_(
            UserGroup.user_uuid == str(user_uuid),
            UserGroup.group_uuid == str(group_uuid),
        )

        with self.new_session() as s:
            return s.query(UserGroup).filter(filter_).delete()
