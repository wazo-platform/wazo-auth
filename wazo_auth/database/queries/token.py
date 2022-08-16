# Copyright 2017-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import time

from .base import BaseDAO
from ..models import Session, Tenant, Token as TokenModel
from ... import exceptions


class TokenDAO(BaseDAO):
    def create(self, body, session_body):
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

    def get_tokens_and_session_that_expire_soon(self, _time):
        tokens = self._get_tokens_with_expiration_less_than(time.time() + _time)
        if not tokens:
            return [], []
        filter_ = TokenModel.uuid.in_([token['uuid'] for token in tokens])
        sessions = self._get_sessions_from_token_filter(filter_)
        return tokens, sessions

    def delete_expired_tokens_and_sessions(self):
        tokens = self._delete_expired_tokens()
        sessions = self._delete_expired_sessions()
        self.session.flush()
        return tokens, sessions

    def _get_tokens_with_expiration_less_than(self, epoch):
        filter_ = TokenModel.expire_t < epoch
        tokens = self.session.query(TokenModel).filter(filter_).all()
        results = []
        for token in tokens:
            results.append(
                {
                    'uuid': token.uuid,
                    'auth_id': token.auth_id,
                    'session_uuid': token.session_uuid,
                    'metadata': json.loads(token.metadata_) if token.metadata_ else {},
                }
            )
        return results

    def _get_sessions_from_token_filter(self, filter_):
        sessions = (
            self.session.query(Session.uuid).outerjoin(TokenModel).filter(filter_).all()
        )
        results = []
        for session in sessions:
            results.append({'uuid': session.uuid})
        return results

    def _delete_expired_tokens(self):
        results = self._get_tokens_with_expiration_less_than(time.time())
        if not results:
            return results
        token_uuids = [token['uuid'] for token in results]
        filter_ = TokenModel.uuid.in_(token_uuids)
        self.session.query(TokenModel).filter(filter_).delete(synchronize_session=False)
        self.session.flush()
        return results

    def _delete_expired_sessions(self):
        filter_ = TokenModel.uuid.is_(None)
        results = self._get_sessions_from_token_filter(filter_)
        if not results:
            return results
        session_uuids = [session['uuid'] for session in results]
        filter_ = Session.uuid.in_(session_uuids)
        self.session.query(Session).filter(filter_).delete(synchronize_session=False)
        self.session.flush()
        return results
