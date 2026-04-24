# Copyright 2017-2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import time
from collections.abc import Iterator
from typing import Any, TypedDict

from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Bundle
from sqlalchemy.sql import cast

from wazo_auth import exceptions

from ..models import Session, Tenant
from ..models import Token as TokenModel
from .base import BaseDAO


class TokenIdentity(TypedDict):
    uuid: str
    auth_id: str


class SessionIdentity(TypedDict):
    uuid: str
    tenant_uuid: str


class TokenRecord(TokenIdentity):
    pbx_user_uuid: str | None
    xivo_uuid: str | None
    issued_t: int
    expire_t: int
    acl: list[str]
    metadata: dict[str, Any]
    session_uuid: str
    remote_addr: str | None
    user_agent: str | None
    refresh_token_uuid: str | None


class ExpiringTokenRow(TokenIdentity):
    session_uuid: str
    metadata: dict[str, Any]


class ExpiringSessionRow(TypedDict):
    uuid: str


class TokenDAO(BaseDAO):
    def create(
        self,
        body: dict[str, Any],
        session_body: dict[str, Any],
        refresh_token_uuid: str | None = None,
    ) -> tuple[str, str]:
        serialized_metadata = json.dumps(body.get('metadata', {}))
        token = TokenModel(
            auth_id=body['auth_id'],
            pbx_user_uuid=body['pbx_user_uuid'],
            xivo_uuid=body['xivo_uuid'],
            issued_t=int(body['issued_t']),
            expire_t=int(body['expire_t']),
            user_agent=body['user_agent'],
            remote_addr=body['remote_addr'],
            metadata_=serialized_metadata,
            acl=body.get('acl') or [],
            refresh_token_uuid=refresh_token_uuid,
        )

        if not session_body.get('tenant_uuid'):
            session_body['tenant_uuid'] = self._get_default_tenant_uuid()
        token.session = Session(**session_body)

        self.session.add(token)
        self.session.flush()
        assert token.uuid is not None and token.session_uuid is not None
        return token.uuid, token.session_uuid

    def _get_default_tenant_uuid(self) -> str:
        filter_ = Tenant.uuid == Tenant.parent_uuid
        return self.session.query(Tenant).filter(filter_).first().uuid

    def get(self, token_uuid: str) -> TokenRecord:
        token = self.session.get(TokenModel, str(token_uuid))
        if token:
            return TokenRecord(
                uuid=token.uuid,
                auth_id=token.auth_id,
                pbx_user_uuid=token.pbx_user_uuid,
                xivo_uuid=token.xivo_uuid,
                issued_t=token.issued_t,
                expire_t=token.expire_t,
                acl=token.acl,
                metadata=json.loads(token.metadata_) if token.metadata_ else {},
                session_uuid=token.session_uuid,
                remote_addr=token.remote_addr,
                user_agent=token.user_agent,
                refresh_token_uuid=token.refresh_token_uuid,
            )

        raise exceptions.UnknownTokenException()

    def list_by_refresh_token(self, refresh_token_uuid: str) -> list[TokenIdentity]:
        filter_ = TokenModel.refresh_token_uuid == str(refresh_token_uuid)
        query = self.session.query(TokenModel).filter(filter_)
        return [
            TokenIdentity(uuid=token.uuid, auth_id=token.auth_id)
            for token in query.all()
        ]

    # TODO: change type signature, use None instead of {} when token not found
    def delete(
        self, token_uuid: str
    ) -> tuple[TokenIdentity | dict[str, Any], SessionIdentity | dict[str, Any]]:
        filter_ = TokenModel.uuid == str(token_uuid)

        session_result: SessionIdentity | dict[str, Any] = {}
        token = self.session.query(TokenModel).filter(filter_).first()
        if not token:
            return {}, {}

        session = token.session
        if len(session.tokens) == 1:
            session_result = SessionIdentity(
                uuid=session.uuid,
                tenant_uuid=session.tenant_uuid,
            )
            self.session.delete(session)

        token_result = TokenIdentity(uuid=token.uuid, auth_id=token.auth_id)
        self.session.query(TokenModel).filter(filter_).delete()
        self.session.flush()

        return token_result, session_result

    def _get_tokens_and_sessions_by_expiration(
        self,
        time_remaining: float,
        limit: int | None = None,
        offset: int | None = None,
    ) -> tuple[list[ExpiringTokenRow], list[ExpiringSessionRow]] | None:
        query = (
            self.session.query(
                Bundle(
                    'token',
                    TokenModel.uuid,
                    TokenModel.auth_id,
                    TokenModel.session_uuid,
                    cast(TokenModel.metadata_, JSONB).label('metadata'),
                ),
                Bundle('session', Session.uuid),
            )
            .filter(TokenModel.expire_t < time.time() + time_remaining)
            .order_by(TokenModel.expire_t)
            .join(TokenModel.session)
        )

        if limit:
            query = query.limit(limit)

        if offset:
            query = query.offset(offset)

        results = query.all()
        if not results:
            return None
        tokens = [
            ExpiringTokenRow(
                uuid=result.token.uuid,
                auth_id=result.token.auth_id,
                session_uuid=result.token.session_uuid,
                metadata=result.token.metadata,
            )
            for result in results
        ]
        sessions = [ExpiringSessionRow(uuid=result.session.uuid) for result in results]

        return tokens, sessions

    def purge_expired_tokens_and_sessions(
        self, batch_size: int = 5_000
    ) -> Iterator[tuple[list[ExpiringTokenRow], list[ExpiringSessionRow]]]:
        while batch := self._get_tokens_and_sessions_by_expiration(0, batch_size):
            tokens, sessions = batch

            uuids = [session['uuid'] for session in sessions]
            self.session.query(Session).filter(Session.uuid.in_(uuids)).delete(
                synchronize_session=False
            )
            self.session.flush()

            yield tokens, sessions
            if len(tokens) < batch_size:
                return

    def get_tokens_and_sessions_about_to_expire(
        self, time_remaining: float, batch_size: int = 5_000
    ) -> Iterator[tuple[list[ExpiringTokenRow], list[ExpiringSessionRow]]]:
        offset = 0
        while batch := self._get_tokens_and_sessions_by_expiration(
            time_remaining, batch_size, offset
        ):
            tokens, sessions = batch
            yield tokens, sessions
            offset += batch_size

            if len(tokens) < batch_size:
                return
