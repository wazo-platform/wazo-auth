# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from sqlalchemy import and_, or_, text
from ..models import Email, Group, Policy, Tenant, User, UserGroup


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

default_search_filter = SearchFilter()
group_search_filter = SearchFilter(Group.name)
policy_search_filter = SearchFilter(Policy.name, Policy.description)
tenant_search_filter = SearchFilter(Tenant.name)
user_search_filter = SearchFilter(User.username, Email.address)
