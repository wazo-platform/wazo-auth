# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy.orm import Query

from ...models import Session
from ..base import QueryPaginator


def sql(query):
    return ' '.join(str(query).split())


def test_the_tiebreaker_is_appended_to_the_requested_order():
    paginator = QueryPaginator({'mobile': Session.mobile}, [Session.uuid])

    query = paginator.update_query(Query([Session]), order='mobile', direction='desc')

    assert sql(query).endswith(
        'ORDER BY auth_session.mobile DESC, auth_session.uuid ASC'
    )


def test_the_tiebreaker_is_not_repeated_when_it_is_the_requested_order():
    paginator = QueryPaginator({'uuid': Session.uuid}, [Session.uuid])

    query = paginator.update_query(Query([Session]), order='uuid', direction='asc')

    assert sql(query).endswith('ORDER BY auth_session.uuid ASC')


def test_the_tiebreaker_is_not_applied_without_a_requested_order():
    paginator = QueryPaginator({'mobile': Session.mobile}, [Session.uuid])

    query = paginator.update_query(Query([Session]), limit=2)

    assert 'ORDER BY' not in sql(query)
