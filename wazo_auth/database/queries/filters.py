# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from sqlalchemy import and_, or_, text
from ..models import (
    Email,
    Group,
    GroupPolicy,
    Policy,
    Tenant,
    TenantUser,
    User,
    UserGroup,
    UserPolicy,
)


class SearchFilter(object):

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


class StrictFilter(object):

    def __init__(self, *column_configs):
        self._column_configs = column_configs

    def new_filter(self, **kwargs):
        filter_ = text('true')

        for key, column, type_ in self._column_configs:
            if key not in kwargs:
                continue
            value = type_(kwargs[key]) if type_ else kwargs[key]
            filter_ = and_(filter_, column == value)

        return filter_


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
)
tenant_strict_filter = StrictFilter(
    ('uuid', Tenant.uuid, str),
    ('name', Tenant.name, None),
    ('user_uuid', TenantUser.user_uuid, str),
)
user_strict_filter = StrictFilter(
    ('uuid', User.uuid, str),
    ('username', User.username, None),
    ('email_address', Email.address, None),
    ('tenant_uuid', TenantUser.tenant_uuid, str),
    ('group_uuid', UserGroup.group_uuid, str),
)

default_search_filter = SearchFilter()
group_search_filter = SearchFilter(Group.name)
policy_search_filter = SearchFilter(Policy.name, Policy.description)
tenant_search_filter = SearchFilter(Tenant.name)
user_search_filter = SearchFilter(User.username, Email.address)
