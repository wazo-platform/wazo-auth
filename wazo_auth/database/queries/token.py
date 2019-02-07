# Copyright 2017-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import time

from .base import BaseDAO
from ..models import ACL, Token as TokenModel, Session
from ... import exceptions


class TokenDAO(BaseDAO):

    def create(self, body):
        serialized_metadata = json.dumps(body.get('metadata', {}))
        token = TokenModel(
            auth_id=body['auth_id'],
            user_uuid=body['xivo_user_uuid'],
            xivo_uuid=body['xivo_uuid'],
            issued_t=int(body['issued_t']),
            expire_t=int(body['expire_t']),
            metadata_=serialized_metadata,
            session_uuid=body['session_uuid'],
        )
        token.acls = [ACL(token_uuid=token.uuid, value=acl) for acl in body.get('acls') or []]
        with self.new_session() as s:
            s.add(token)
            s.commit()
            return token.uuid

    def get(self, token_uuid):
        with self.new_session() as s:
            token = s.query(TokenModel).get(token_uuid)
            if token:
                return {
                    'uuid': token.uuid,
                    'auth_id': token.auth_id,
                    'xivo_user_uuid': token.user_uuid,
                    'xivo_uuid': token.xivo_uuid,
                    'issued_t': token.issued_t,
                    'expire_t': token.expire_t,
                    'acls': [acl.value for acl in token.acls],
                    'metadata': json.loads(token.metadata_) if token.metadata_ else {},
                    'session_uuid': token.session_uuid,
                }

            raise exceptions.UnknownTokenException()

    def delete(self, token_uuid):
        filter_ = TokenModel.uuid == token_uuid

        with self.new_session() as s:
            s.query(TokenModel).filter(filter_).delete()

    def delete_expired_tokens_and_sessions(self):
        with self.new_session() as s:
            tokens = self._delete_expired_tokens(s)
            sessions = self._delete_expired_sessions(s)

        return tokens, sessions

    def _delete_expired_tokens(self, s):
        filter_ = TokenModel.expire_t < time.time()
        tokens = s.query(TokenModel).filter(filter_).all()

        if not tokens:
            return []

        results = []
        for token in tokens:
            results.append({
                'uuid': token.uuid,
                'auth_id': token.auth_id,
                'session_uuid': token.session_uuid,
            })

        token_uuids = [token.uuid for token in tokens]
        filter_ = TokenModel.uuid.in_(token_uuids)
        s.query(TokenModel).filter(filter_).delete(synchronize_session=False)
        return results

    def _delete_expired_sessions(self, s):
        filter_ = TokenModel.uuid == None
        sessions = s.query(Session.uuid).outerjoin(TokenModel).filter(filter_).all()

        if not sessions:
            return []

        results = []
        for session in sessions:
            results.append({
                'uuid': session.uuid,
            })

        filter_ = Session.uuid.in_(sessions)
        s.query(Session).filter(filter_).delete(synchronize_session=False)
        return results
