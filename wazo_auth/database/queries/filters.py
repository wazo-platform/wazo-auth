# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from sqlalchemy import or_, text
from ..models import Email, Group, Policy, Tenant, User


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


default_search_filter = SearchFilter()
group_search_filter = SearchFilter(Group.name)
policy_search_filter = SearchFilter(Policy.name, Policy.description)
tenant_search_filter = SearchFilter(Tenant.name)
user_search_filter = SearchFilter(User.username, Email.address)
