# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from collections import OrderedDict
from sqlalchemy import and_, exc, text
from .base import BaseDAO, PaginatorMixin
from . import filters
from ..models import (
    Email,
    Group,
    Policy,
    Tenant,
    TenantUser,
    User,
    UserEmail,
    UserGroup,
    UserPolicy,
)
from ... import exceptions


class UserDAO(filters.FilterMixin, PaginatorMixin, BaseDAO):

    constraint_to_column_map = dict(
        auth_user_pkey='uuid',
        auth_user_username_key='username',
        auth_email_address_key='email_address',
    )
    search_filter = filters.user_search_filter
    strict_filter = filters.user_strict_filter
    column_map = dict(
        username=User.username,
    )

    def add_policy(self, user_uuid, policy_uuid):
        user_policy = UserPolicy(user_uuid=user_uuid, policy_uuid=policy_uuid)
        with self.new_session() as s:
            s.add(user_policy)
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    # This association already exists.
                    s.rollback()
                    return
                if e.orig.pgcode == self._FKEY_CONSTRAINT_CODE:
                    constraint = e.orig.diag.constraint_name
                    if constraint == 'auth_user_policy_user_uuid_fkey':
                        raise exceptions.UnknownUserException(user_uuid)
                    elif constraint == 'auth_user_policy_policy_uuid_fkey':
                        raise exceptions.UnknownPolicyException(policy_uuid)
                raise

    def change_password(self, user_uuid, salt, hash_):
        filter_ = User.uuid == str(user_uuid)
        values = dict(
            password_salt=salt,
            password_hash=hash_,
        )

        with self.new_session() as s:
            s.query(User).filter(filter_).update(values)

    def exists(self, user_uuid):
        return self.count(uuid=user_uuid) > 0

    def remove_policy(self, user_uuid, policy_uuid):
        filter_ = and_(
            UserPolicy.user_uuid == user_uuid,
            UserPolicy.policy_uuid == policy_uuid,
        )

        with self.new_session() as s:
            return s.query(UserPolicy).filter(filter_).delete()

    def count(self, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = self.new_strict_filter(**kwargs)
            search_filter = self.new_search_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        with self.new_session() as s:
            return s.query(User).join(
                UserEmail, UserEmail.user_uuid == User.uuid,
            ).join(
                Email, Email.uuid == UserEmail.email_uuid
            ).filter(filter_).count()

    def count_groups(self, user_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = filters.group_strict_filter.new_filter(**kwargs)
            search_filter = filters.group_search_filter.new_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, UserGroup.user_uuid == str(user_uuid))

        with self.new_session() as s:
            return s.query(Group).join(UserGroup).filter(filter_).count()

    def count_policies(self, user_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = filters.policy_strict_filter.new_filter(**kwargs)
            search_filter = filters.policy_search_filter.new_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, UserPolicy.user_uuid == user_uuid)

        with self.new_session() as s:
            return s.query(Policy).join(
                UserPolicy, UserPolicy.policy_uuid == Policy.uuid,
            ).filter(filter_).count()

    def count_tenants(self, user_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = filters.tenant_strict_filter.new_filter(**kwargs)
            search_filter = filters.tenant_search_filter.new_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, TenantUser.user_uuid == str(user_uuid))

        with self.new_session() as s:
            return s.query(Tenant).join(TenantUser).filter(filter_).count()

    def create(self, username, **kwargs):
        user_args = dict(
            username=username,
            password_hash=kwargs.get('hash_'),
            password_salt=kwargs.get('salt'),
        )
        uuid = kwargs.get('uuid')
        if uuid:
            user_args['uuid'] = str(uuid)

        email_confirmed = kwargs.get('email_confirmed', False)
        email_address = kwargs.get('email_address', None)
        with self.new_session() as s:
            try:
                if email_address:
                    email_args = dict(address=email_address, confirmed=email_confirmed)
                    email = Email(**email_args)
                    s.add(email)

                user = User(**user_args)
                s.add(user)
                s.flush()
                if email_address:
                    user_email = UserEmail(
                        user_uuid=user.uuid,
                        email_uuid=email.uuid,
                        main=True,
                    )
                    s.add(user_email)
                    s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                    column = self.constraint_to_column_map.get(e.orig.diag.constraint_name)
                    value = locals().get(column)
                    if column:
                        raise exceptions.ConflictException('users', column, value)
                raise

            if email_address:
                emails = [{'address': email_address, 'confirmed': email_confirmed, 'main': True}]
            else:
                emails = []

            return dict(
                uuid=user.uuid,
                username=username,
                emails=emails
            )

    def delete(self, user_uuid):
        with self.new_session() as s:
            rows = s.query(UserEmail.email_uuid).filter(UserEmail.user_uuid == user_uuid).all()
            email_ids = [row.email_uuid for row in rows]
            if email_ids:
                s.query(Email).filter(Email.uuid.in_(email_ids)).delete(synchronize_session=False)
            nb_deleted = s.query(User).filter(User.uuid == user_uuid).delete()

        if not nb_deleted:
            raise exceptions.UnknownUserException(user_uuid)

    def get_credentials(self, username):
        filter_ = self.new_strict_filter(username=username)
        with self.new_session() as s:
            query = s.query(
                User.password_salt,
                User.password_hash,
            ).filter(filter_)

            for row in query.all():
                return row.password_hash, row.password_salt

            raise exceptions.UnknownUsernameException(username)

    def list_(self, **kwargs):
        users = OrderedDict()

        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self.new_strict_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)

        with self.new_session() as s:
            query = s.query(
                User.uuid,
                User.username,
                UserEmail.main,
                Email.uuid,
                Email.address,
                Email.confirmed,
            ).join(
                UserEmail, User.uuid == UserEmail.user_uuid,
            ).join(
                Email, Email.uuid == UserEmail.email_uuid,
            ).outerjoin(TenantUser).outerjoin(UserGroup).filter(filter_)
            query = self._paginator.update_query(query, **kwargs)
            rows = query.all()

            for user_uuid, username, main_email, email_uuid, address, confirmed in rows:
                if user_uuid not in users:
                    users[user_uuid] = dict(
                        username=username,
                        uuid=user_uuid,
                        emails=[],
                    )

                email = dict(
                    address=address,
                    main=main_email,
                    confirmed=confirmed,
                )
                users[user_uuid]['emails'].append(email)

        return users.values()
