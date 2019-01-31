# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import and_, or_, text
from ..models import (
    Email,
    ExternalAuthType,
    Group,
    GroupPolicy,
    Policy,
    Tenant,
    User,
    UserGroup,
    UserPolicy,
)


class SearchFilter:

    def __init__(self, *columns):
        self._columns = columns

    def new_filter(self, search=None, **ignored):
        if search is None:
            return text('true')

        if not search:
            pattern = '%'
        else:
            words = [w for w in search.split(' ') if w]
            pattern = '%{}%'.format('%'.join(words))

        return or_(column.ilike(pattern) for column in self._columns)


class StrictFilter:

    def __init__(self, *column_configs):
        self._column_configs = column_configs

    def new_filter(self, **kwargs):
        filter_ = text('true')

        for key, column, type_ in self._column_configs:
            if key not in kwargs:
                continue

            value = type_(kwargs[key]) if type_ else kwargs[key]
            if isinstance(value, list):
                filter_ = and_(filter_, column.in_(value))
            else:
                filter_ = and_(filter_, column == value)

        return filter_


class FilterMixin:

    search_filter = SearchFilter()
    strict_filter = StrictFilter()

    def new_search_filter(self, **kwargs):
        return self.search_filter.new_filter(**kwargs)

    def new_strict_filter(self, **kwargs):
        return self.strict_filter.new_filter(**kwargs)


external_auth_strict_filter = StrictFilter(
    ('type', ExternalAuthType.name, None),
)
group_strict_filter = StrictFilter(
    ('uuid', Group.uuid, str),
    ('name', Group.name, None),
    ('user_uuid', UserGroup.user_uuid, str),
)
policy_strict_filter = StrictFilter(
    ('uuid', Policy.uuid, str),
    ('name', Policy.name, None),
    ('user_uuid', UserPolicy.user_uuid, str),
    ('group_uuid', GroupPolicy.group_uuid, str),
    ('tenant_uuid', Policy.tenant_uuid, str),
)
tenant_strict_filter = StrictFilter(
    ('uuid', Tenant.uuid, str),
    ('uuids', Tenant.uuid, list),
    ('name', Tenant.name, None),
)
user_strict_filter = StrictFilter(
    ('uuid', User.uuid, str),
    ('username', User.username, None),
    ('firstname', User.firstname, None),
    ('lastname', User.lastname, None),
    ('purpose', User.purpose, None),
    ('email_address', Email.address, None),
    ('group_uuid', UserGroup.group_uuid, str),
)

external_auth_search_filter = SearchFilter(ExternalAuthType.name)
group_search_filter = SearchFilter(Group.name)
policy_search_filter = SearchFilter(Policy.name, Policy.description)
tenant_search_filter = SearchFilter(Tenant.name)
user_search_filter = SearchFilter(User.firstname, User.lastname, User.username, Email.address)
