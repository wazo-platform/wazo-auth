# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wazo_auth.services.saml import RequestId

from sqlalchemy import exc

from wazo_auth import exceptions
from wazo_auth.services.saml import SamlAuthContext, SamlSessionItem

from ..models import SAMLSession
from . import filters
from .base import BaseDAO


class SAMLSessionDAO(filters.FilterMixin, BaseDAO):
    search_filter = filters.saml_session_strict_filter

    def _forge_return(self, session: SAMLSession) -> SamlSessionItem:
        return SamlSessionItem(
            session.request_id,
            SamlAuthContext(
                session.session_id,
                session.redirect_url,
                session.domain,
                session.relay_state,
                session.login,
                session.start_time,
                session.saml_name_id,
                session.refresh_token_uuid,
            ),
        )

    def _get_raw(self, request_id: RequestId):
        return (
            self.session.query(SAMLSession)
            .filter(SAMLSession.request_id == request_id)
            .first()
        )

    def get(self, request_id: RequestId) -> SamlSessionItem:
        session = self._get_raw(request_id)
        if session:
            return self._forge_return(session)
        raise exceptions.UnknownSAMLSessionException(request_id)

    def list(self, **kwargs) -> list[SamlSessionItem]:
        search_filter = self.new_search_filter(**kwargs)
        all_rows = self.session.query(SAMLSession).filter(search_filter).all()
        return [self._forge_return(session) for session in all_rows]

    def create(self, item: SamlSessionItem) -> SamlSessionItem:
        saml_session = SAMLSession(
            request_id=item.request_id,
            session_id=item.auth_context.saml_session_id,
            redirect_url=item.auth_context.redirect_url,
            domain=item.auth_context.domain,
            relay_state=item.auth_context.relay_state,
            login=item.auth_context.login,
            start_time=item.auth_context.start_time,
            saml_name_id=item.auth_context.saml_name_id,
            refresh_token_uuid=item.auth_context.refresh_token_uuid,
        )
        self.session.add(saml_session)
        try:
            self.session.flush()
        except exc.IntegrityError as e:
            self.session.rollback()
            raise exceptions.DuplicatedSAMLSessionException(
                f'Session with request_id({item.request_id}) or '
                f'session_id({item.auth_context.saml_session_id} already exists, error: {e}'
            )
        except Exception as e:
            self.session.rollback()
            raise exceptions.SAMLSessionSQLException(
                f'Unexpected error on SAML session SQL creation for {item.request_id}: {e}'
            )

        return item

    def update(self, request_id, **kwargs):
        filter_ = SAMLSession.request_id == request_id
        session_db: SAMLSession = self._get_raw(request_id)
        if not session_db:
            raise exceptions.UnknownSAMLSessionException(request_id)
        session = {
            'session_id': session_db.session_id,
            'redirect_url': session_db.redirect_url,
            'domain': session_db.domain,
            'relay_state': session_db.relay_state,
            'login': session_db.login,
            'start_time': session_db.start_time,
            'saml_name_id': session_db.saml_name_id,
            'refresh_token_uuid': session_db.refresh_token_uuid,
        }
        session.update(kwargs)

        try:
            self.session.query(SAMLSession).filter(filter_).update(session)
            self.session.flush()
        except exc.IntegrityError as e:
            self.session.rollback()
            raise exceptions.SAMLSessionSQLException(
                f'Unexpected error on update of SAML session for {request_id}: {e.orig.pgcode}'
            )

    def delete(self, request_id) -> None:
        filter_ = SAMLSession.request_id == request_id
        self.session.query(SAMLSession).filter(filter_).delete(
            synchronize_session=False
        )
        self.session.flush()
