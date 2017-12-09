# -*- coding: utf-8 -*-
# Copyright 2016-2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import json
from sqlalchemy import and_, exc
from .base import BaseDAO, PaginatorMixin
from . import filters
from ..models import ExternalAuthData, ExternalAuthType, User, UserExternalAuth
from ... import exceptions


class ExternalAuthDAO(filters.FilterMixin, PaginatorMixin, BaseDAO):

    search_filter = filters.external_auth_search_filter
    strict_filter = filters.external_auth_strict_filter
    column_map = dict(
        type=ExternalAuthType.name,
    )

    def create(self, user_uuid, auth_type, data):
        serialized_data = json.dumps(data)
        with self.new_session() as s:
            external_type = self._find_or_create_type(s, auth_type)
            external_data = ExternalAuthData(data=serialized_data)
            s.add(external_data)
            s.commit()
            user_external_auth = UserExternalAuth(
                user_uuid=str(user_uuid),
                external_auth_type_uuid=external_type.uuid,
                external_auth_data_uuid=external_data.uuid,
            )
            s.add(user_external_auth)
            try:
                s.commit()
            except exc.IntegrityError as e:
                if e.orig.pgcode in (self._UNIQUE_CONSTRAINT_CODE, self._FKEY_CONSTRAINT_CODE):
                    constraint = e.orig.diag.constraint_name
                    if constraint == 'auth_external_user_type_auth_constraint':
                        raise exceptions.ExternalAuthAlreadyExists(auth_type)
                    elif constraint == 'auth_user_external_auth_user_uuid_fkey':
                        raise exceptions.UnknownUserException(user_uuid)
                raise
            return data

    def delete(self, user_uuid, auth_type):
        with self.new_session() as s:
            type_ = self._find_type(s, auth_type)
            filter_ = and_(
                UserExternalAuth.user_uuid == str(user_uuid),
                UserExternalAuth.external_auth_type_uuid == type_.uuid,
            )

            nb_deleted = s.query(UserExternalAuth).filter(filter_).delete()
            if nb_deleted:
                return

            self._assert_user_exists(s, user_uuid)
            raise exceptions.UnknownExternalAuthException(auth_type)

    def get(self, user_uuid, auth_type):
        filter_ = and_(
            UserExternalAuth.user_uuid == str(user_uuid),
            ExternalAuthType.name == auth_type,
        )

        with self.new_session() as s:
            data = s.query(
                ExternalAuthData.data,
            ).join(UserExternalAuth).join(ExternalAuthType).filter(filter_).first()

            if data:
                return json.loads(data.data)

            self._assert_type_exists(s, auth_type)
            self._assert_user_exists(s, user_uuid)
            raise exceptions.UnknownExternalAuthException(auth_type)

    def list_(self, user_uuid, **kwargs):
        kwargs['user_uuid'] = user_uuid
        search_filter = self.new_search_filter(**kwargs)
        strict_filter = self.new_strict_filter(**kwargs)
        filter_ = and_(search_filter, strict_filter)

        result = []

        with self.new_session() as s:
            query = s.query(
                ExternalAuthData.data,
                ExternalAuthType.name,
            ).join(UserExternalAuth).join(ExternalAuthType).filter(filter_)
            query = self._paginator.update_query(query, **kwargs)
            for row in query.all():
                result.append({'type': row.name, 'data': json.loads(row.data)})

        return result

    def update(self, user_uuid, auth_type, data):
        self.delete(user_uuid, auth_type)
        return self.create(user_uuid, auth_type, data)

    def _assert_type_exists(self, s, auth_type):
        self._find_type(s, auth_type)

    def _assert_user_exists(self, s, user_uuid):
        if s.query(User).filter(User.uuid == str(user_uuid)).count() == 0:
            raise exceptions.UnknownUserException(user_uuid)

    def _find_type(self, s, auth_type):
        type_ = s.query(ExternalAuthType).filter(ExternalAuthType.name == auth_type).first()
        if type_:
            return type_
        raise exceptions.UnknownExternalAuthTypeException(auth_type)

    def _find_or_create_type(self, s, auth_type):
        try:
            type_ = self._find_type(s, auth_type)
        except exceptions.UnknownExternalAuthTypeException:
            type_ = ExternalAuthType(name=auth_type)
            s.add(type_)
        return type_
