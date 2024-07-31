# Copyright 2017-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import time

from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Bundle
from sqlalchemy.sql import cast

from ... import exceptions
from ..models import Session, Tenant
from ..models import Token as TokenModel
from .base import BaseDAO


class TokenDAO(BaseDAO):
    def create(self, body, session_body, refresh_token_uuid=None):
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
        return token.uuid, token.session_uuid

    def _get_default_tenant_uuid(self):
        filter_ = Tenant.uuid == Tenant.parent_uuid
        return self.session.query(Tenant).filter(filter_).first().uuid

    def get(self, token_uuid):
        token = self.session.query(TokenModel).get(str(token_uuid))
        if token:
            return {
                'uuid': token.uuid,
                'auth_id': token.auth_id,
                'pbx_user_uuid': token.pbx_user_uuid,
                'xivo_uuid': token.xivo_uuid,
                'issued_t': token.issued_t,
                'expire_t': token.expire_t,
                'acl': token.acl,
                'metadata': json.loads(token.metadata_) if token.metadata_ else {},
                'session_uuid': token.session_uuid,
                'remote_addr': token.remote_addr,
                'user_agent': token.user_agent,
                'refresh_token_uuid': token.refresh_token_uuid,
            }

        raise exceptions.UnknownTokenException()

    def delete(self, token_uuid):
        filter_ = TokenModel.uuid == str(token_uuid)

        session_result = {}
        token = self.session.query(TokenModel).filter(filter_).first()
        if not token:
            return {}, {}

        session = token.session
        if len(session.tokens) == 1:
            session_result = {
                'uuid': session.uuid,
                'tenant_uuid': session.tenant_uuid,
            }
            self.session.delete(session)

        token_result = {'uuid': token.uuid, 'auth_id': token.auth_id}
        self.session.query(TokenModel).filter(filter_).delete()
        self.session.flush()

        return token_result, session_result

    def _get_tokens_and_sessions_by_expiration(
        self, time_remaining, limit=None, offset=None
    ):
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
        tokens = [result.token._asdict() for result in results]
        sessions = [result.session._asdict() for result in results]

        return tokens, sessions

    def purge_expired_tokens_and_sessions(self, batch_size=5_000):
        def delete_by_uuids(model, items):
            uuids = [item['uuid'] for item in items]
            self.session.query(model).filter(model.uuid.in_(uuids)).delete(
                synchronize_session=False
            )
            self.session.flush()

        while batch := self._get_tokens_and_sessions_by_expiration(0, batch_size):
            tokens, sessions = batch
            delete_by_uuids(TokenModel, tokens)
            delete_by_uuids(Session, sessions)
            yield tokens, sessions

            if len(tokens) < batch_size:
                return

    def get_tokens_and_sessions_about_to_expire(self, time_remaining, batch_size=5_000):
        offset = 0
        while batch := self._get_tokens_and_sessions_by_expiration(
            time_remaining, batch_size, offset
        ):
            tokens, sessions = batch
            yield tokens, sessions
            offset += batch_size

            if len(tokens) < batch_size:
                return
