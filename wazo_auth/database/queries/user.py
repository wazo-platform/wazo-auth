# Copyright 2017-2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import and_, or_, exc, func, text
from sqlalchemy.orm import joinedload
from .base import BaseDAO, PaginatorMixin
from . import filters
from ..models import (
    Email,
    Group,
    GroupPolicy,
    Policy,
    Session,
    Token,
    User,
    UserGroup,
    UserPolicy,
)
from ... import exceptions


class UserDAO(filters.FilterMixin, PaginatorMixin, BaseDAO):

    constraint_to_column_map = {
        'auth_user_pkey': 'uuid',
        'auth_user_username_key': 'username',
        'auth_email_address_key': 'email_address',
    }
    search_filter = filters.user_search_filter
    strict_filter = filters.user_strict_filter
    column_map = {
        'username': User.username,
        'firstname': User.firstname,
        'lastname': User.lastname,
    }

    def add_policy(self, user_uuid, policy_uuid):
        user_policy = UserPolicy(user_uuid=user_uuid, policy_uuid=policy_uuid)
        self.session.begin_nested()
        self.session.add(user_policy)
        try:
            self.session.commit()
        except exc.IntegrityError as e:
            self.session.rollback()
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                # This association already exists.
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
        values = {'password_salt': salt, 'password_hash': hash_}

        self.session.query(User).filter(filter_).update(values)
        self.session.flush()

    def exists(self, user_uuid, tenant_uuids=None):
        kwargs = {'uuid': user_uuid}
        if tenant_uuids is not None:
            kwargs['tenant_uuids'] = tenant_uuids
        return self.count(**kwargs) > 0

    def remove_policy(self, user_uuid, policy_uuid):
        filter_ = and_(
            UserPolicy.user_uuid == str(user_uuid),
            UserPolicy.policy_uuid == str(policy_uuid),
        )

        result = self.session.query(UserPolicy).filter(filter_).delete()
        self.session.flush()
        return result

    def count(self, **kwargs):
        filter_ = text('true')

        tenant_uuid = kwargs.get('tenant_uuid')
        if tenant_uuid:
            filter_ = User.tenant_uuid == str(tenant_uuid)

        tenant_uuids = kwargs.get('tenant_uuids')
        if tenant_uuids:
            filter_ = User.tenant_uuid.in_(tenant_uuids)

        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = self.new_strict_filter(**kwargs)
            search_filter = self.new_search_filter(**kwargs)
            filter_ = and_(filter_, strict_filter, search_filter)

            policy_uuid = kwargs.get('policy_uuid')
            if policy_uuid:
                filter_ = and_(filter_, self._policy_uuid_filter(policy_uuid))

            policy_slug = kwargs.get('policy_slug')
            if policy_slug:
                filter_ = and_(filter_, self._policy_slug_filter(policy_slug))

            has_policy_uuid = kwargs.get('has_policy_uuid')
            if has_policy_uuid:
                filter_ = and_(filter_, self._has_policy_uuid_filter(has_policy_uuid))

            has_policy_slug = kwargs.get('has_policy_slug')
            if has_policy_slug:
                filter_ = and_(filter_, self._has_policy_slug_filter(has_policy_slug))

        return self.session.query(User.uuid).outerjoin(Email).filter(filter_).count()

    def count_groups(self, user_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = filters.group_strict_filter.new_filter(**kwargs)
            search_filter = filters.group_search_filter.new_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, UserGroup.user_uuid == str(user_uuid))

        return self.session.query(Group).join(UserGroup).filter(filter_).count()

    def count_sessions(self, user_uuid, **kwargs):
        # filtered is not implemented

        filter_ = Token.auth_id == str(user_uuid)

        return self.session.query(Session).join(Token).filter(filter_).count()

    def count_policies(self, user_uuid, **kwargs):
        filtered = kwargs.get('filtered')
        if filtered is not False:
            strict_filter = filters.policy_strict_filter.new_filter(**kwargs)
            search_filter = filters.policy_search_filter.new_filter(**kwargs)
            filter_ = and_(strict_filter, search_filter)
        else:
            filter_ = text('true')

        filter_ = and_(filter_, UserPolicy.user_uuid == str(user_uuid))

        return (
            self.session.query(Policy)
            .join(UserPolicy, UserPolicy.policy_uuid == Policy.uuid)
            .filter(filter_)
            .count()
        )

    def create(self, **kwargs):
        user_args = {
            'username': kwargs.get('username'),
            'firstname': kwargs.get('firstname'),
            'lastname': kwargs.get('lastname'),
            'password_hash': kwargs.get('hash_'),
            'password_salt': kwargs.get('salt'),
            'purpose': kwargs['purpose'],
            'enabled': kwargs.get('enabled'),
            'tenant_uuid': kwargs['tenant_uuid'],
        }
        uuid = kwargs.get('uuid')
        if uuid:
            user_args['uuid'] = str(uuid)

        email_confirmed = kwargs.get('email_confirmed', False)
        email_address = kwargs.get('email_address', None)
        try:
            user = User(**user_args)
            self.session.add(user)
            self.session.flush()

            if email_address:
                email = Email(
                    address=email_address,
                    confirmed=email_confirmed,
                    main=True,
                    user_uuid=user.uuid,
                )
                self.session.add(email)

            self.session.flush()
        except exc.IntegrityError as e:
            self.session.rollback()
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                column = self.constraint_to_column_map.get(e.orig.diag.constraint_name)
                value = locals().get(column)
                if column:
                    raise exceptions.ConflictException('users', column, value)
            raise

        emails = []
        if email_address:
            emails.append(
                {
                    'uuid': email.uuid,
                    'address': email_address,
                    'confirmed': email_confirmed,
                    'main': True,
                }
            )

        return {
            'uuid': user.uuid,
            'username': user.username,
            'firstname': user.firstname,
            'lastname': user.lastname,
            'purpose': user.purpose,
            'emails': emails,
            'enabled': user.enabled,
            'tenant_uuid': user.tenant_uuid,
        }

    def delete(self, user_uuid):
        user = self.session.query(User).filter(User.uuid == str(user_uuid)).first()
        if not user:
            raise exceptions.UnknownUserException(user_uuid)
        self.session.delete(user)
        self.session.flush()

    def get_credentials(self, user_uuid):
        query = self.session.query(User.password_salt, User.password_hash).filter(
            and_(
                User.uuid == user_uuid,
                User.enabled.is_(True),
            )
        )

        row = query.first()
        if not row:
            raise exceptions.UnknownUserUUIDException(user_uuid)
        return row.password_hash, row.password_salt

    def get_user_uuid_by_login(self, login):
        if not login:
            raise exceptions.UnknownLoginException(login)

        email_filter = func.lower(Email.address) == func.lower(login)
        query = (
            self.session.query(User.uuid)
            .outerjoin(Email)
            .filter(
                and_(
                    email_filter,
                    Email.confirmed.is_(True),
                )
            )
        )
        row = query.first()
        if row:
            return row.uuid

        username_filter = func.lower(User.username) == func.lower(login)
        query = self.session.query(User.uuid).filter(and_(username_filter))
        row = query.first()
        if not row:
            raise exceptions.UnknownLoginException(login)
        return row.uuid

    def get_emails(self, user_uuid):
        user = self.session.query(User).filter(User.uuid == str(user_uuid)).first()
        if not user:
            raise exceptions.UnknownUserException(user_uuid)

        result = []
        for email in user.emails:
            result.append(
                {
                    'uuid': email.uuid,
                    'address': email.address,
                    'main': email.main,
                    'confirmed': email.confirmed,
                }
            )
        return result

    def list_(self, **kwargs):
        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self.new_strict_filter(**kwargs)
        filter_ = and_(strict_filter, search_filter)

        tenant_uuids = kwargs.get('tenant_uuids')
        if tenant_uuids is not None:
            filter_ = and_(filter_, User.tenant_uuid.in_(tenant_uuids))

        tenant_uuid = kwargs.get('tenant_uuid')
        if tenant_uuid:
            filter_ = and_(filter_, User.tenant_uuid == str(tenant_uuid))

        policy_uuid = kwargs.get('policy_uuid')
        if policy_uuid:
            filter_ = and_(filter_, self._policy_uuid_filter(policy_uuid))

        policy_slug = kwargs.get('policy_slug')
        if policy_slug:
            filter_ = and_(filter_, self._policy_slug_filter(policy_slug))

        has_policy_uuid = kwargs.get('has_policy_uuid')
        if has_policy_uuid:
            filter_ = and_(filter_, self._has_policy_uuid_filter(has_policy_uuid))

        has_policy_slug = kwargs.get('has_policy_slug')
        if has_policy_slug:
            filter_ = and_(filter_, self._has_policy_slug_filter(has_policy_slug))

        login = kwargs.get('login')
        if login:
            filter_ = and_(filter_, self._login_filter(login))

        users = []
        query = (
            self.session.query(User)
            .outerjoin(Email)
            .outerjoin(UserGroup)
            .options(joinedload('emails'))
            .filter(filter_)
        )
        query = self._paginator.update_query(query, **kwargs)

        for user in query.all():
            emails = []
            for email in user.emails:
                emails.append(
                    {
                        'uuid': email.uuid,
                        'address': email.address,
                        'main': email.main,
                        'confirmed': email.confirmed,
                    }
                )

            users.append(
                {
                    'username': user.username,
                    'uuid': user.uuid,
                    'enabled': user.enabled,
                    'emails': emails,
                    'firstname': user.firstname,
                    'lastname': user.lastname,
                    'purpose': user.purpose,
                    'tenant_uuid': user.tenant_uuid,
                }
            )

        return users

    def update(self, user_uuid, **kwargs):
        self.session.query(User).filter(User.uuid == str(user_uuid)).update(kwargs)
        self.session.flush()

    def update_emails(self, user_uuid, emails):
        existing_addresses = self._emails_to_dict(self.get_emails(user_uuid))
        emails_as_dict = self._emails_to_dict(emails)
        updated_emails = self._merge_existing_emails(emails_as_dict, existing_addresses)

        self._delete_all_emails(user_uuid)

        for email in updated_emails.values():
            self._add_user_email(user_uuid, email)

        self.session.flush()
        return emails

    def login_exists(self, login, ignored_user=None):
        filter_ = self._login_filter(login)
        if ignored_user:
            filter_ = and_(filter_, User.uuid != str(ignored_user))
        query = self.session.query(User.uuid).outerjoin(Email).filter(filter_)
        row = query.first()
        return True if row else False

    def _login_filter(self, login):
        return or_(User.username == login, Email.address == login)

    def _add_user_email(self, user_uuid, args):
        args.setdefault('confirmed', False)
        email = Email(
            uuid=args.get('uuid'),
            address=args['address'],
            confirmed=args['confirmed'],
            main=args['main'],
            user_uuid=user_uuid,
        )
        self.session.add(email)

        try:
            self.session.flush()
        except exc.IntegrityError as e:
            self.session.rollback()
            if e.orig.pgcode == self._UNIQUE_CONSTRAINT_CODE:
                column = self.constraint_to_column_map.get(e.orig.diag.constraint_name)
                value = locals().get(column)
                if column:
                    raise exceptions.ConflictException('users', column, value)
            raise

        args['uuid'] = email.uuid

    def _delete_all_emails(self, user_uuid):
        self.session.query(Email).filter(Email.user_uuid == str(user_uuid)).delete()
        self.session.flush()

    def _policy_uuid_filter(self, policy_uuid):
        return self._policy_filter(Policy.uuid == policy_uuid)

    def _policy_slug_filter(self, policy_slug):
        return self._policy_filter(Policy.slug == policy_slug)

    def _policy_filter(self, filter_):
        user_policy_subquery = (
            self.session.query(User.uuid)
            .join(UserPolicy, User.uuid == UserPolicy.user_uuid)
            .join(Policy, UserPolicy.policy_uuid == Policy.uuid)
            .filter(filter_)
            .subquery()
        )
        return User.uuid.in_(user_policy_subquery)

    def _has_policy_uuid_filter(self, has_policy_uuid):
        return self._has_policy_filter(Policy.uuid == has_policy_uuid)

    def _has_policy_slug_filter(self, has_policy_slug):
        return self._has_policy_filter(Policy.slug == has_policy_slug)

    def _has_policy_filter(self, filter_):
        user_policy_subquery = (
            self.session.query(User.uuid)
            .join(UserPolicy, User.uuid == UserPolicy.user_uuid)
            .join(Policy, UserPolicy.policy_uuid == Policy.uuid)
            .filter(filter_)
            .subquery()
        )
        user_policy_filter = User.uuid.in_(user_policy_subquery)
        group_policy_subquery = (
            self.session.query(User.uuid)
            .join(UserGroup, User.uuid == UserGroup.user_uuid)
            .join(Group, UserGroup.group_uuid == Group.uuid)
            .join(GroupPolicy, Group.uuid == GroupPolicy.group_uuid)
            .join(Policy, GroupPolicy.policy_uuid == Policy.uuid)
            .filter(filter_)
            .subquery()
        )
        group_policy_filter = User.uuid.in_(group_policy_subquery)
        filter_ = or_(
            user_policy_filter.self_group(),
            group_policy_filter.self_group(),
        )
        return filter_

    @staticmethod
    def _emails_to_dict(emails):
        return {email['address']: email for email in emails}

    @staticmethod
    def _merge_existing_emails(new, old):
        for address, email in new.items():
            if address not in old:
                continue

            email['uuid'] = old[address]['uuid']
            if email.get('confirmed') is None:
                email['confirmed'] = old[address]['confirmed']

        return new
