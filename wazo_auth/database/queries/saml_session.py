# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from sqlalchemy import exc

from wazo_auth import exceptions
from wazo_auth.services.saml import RequestId, SamlAuthContext

from ..models import SAMLSession
from .base import BaseDAO


class SAMLSessionDAO(BaseDAO):
    def _forge_return(self, session: SAMLSession) -> tuple[RequestId, SamlAuthContext]:
        return (
            session.request_id,
            SamlAuthContext(
                session.session_id,
                session.redirect_url,
                session.domain,
                session.relay_state,
                session.login,
                session.start_time,
            ),
        )

    def _get_raw(self, request_id: RequestId):
        return (
            self.session.query(SAMLSession)
            .filter(SAMLSession.request_id == request_id)
            .first()
        )

    def get(self, request_id: RequestId) -> tuple[RequestId, SamlAuthContext]:
        session = self._get_raw(request_id)
        if session:
            return self._forge_return(session)
        raise exceptions.UnknownSAMLSessionException(request_id)

    def create(
        self, request_id: RequestId, session: SamlAuthContext
    ) -> tuple[RequestId, SamlAuthContext]:
        saml_session = SAMLSession(
            request_id=request_id,
            session_id=session.saml_session_id,
            redirect_url=session.redirect_url,
            domain=session.domain,
            relay_state=session.relay_state,
            login=session.login,
            start_time=session.start_time,
        )
        self.session.add(saml_session)
        try:
            self.session.flush()
        except exc.IntegrityError as e:
            self.session.rollback()
            raise exceptions.DuplicatedSAMLSessionException(
                f'Session with request_id({request_id}) or '
                f'session_id({session.saml_session_id} already exists, error: {e}'
            )
        except Exception as e:
            self.session.rollback()
            raise exceptions.SAMLSessionSQLException(
                f'Unexpected error on SAML session SQL creation for {request_id}: {e}'
            )
        return (request_id, session)

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
