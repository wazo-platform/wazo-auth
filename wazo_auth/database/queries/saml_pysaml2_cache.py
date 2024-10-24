# adapted from pysaml2 Cache class, see pysaml2 package for licensing details
# Modifications: Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
import logging
from typing import Any

from saml2 import time_util
from saml2.cache import TooOld
from saml2.ident import code, decode
from saml2.saml import NameID
from sqlalchemy import exc

from ..models import SAMLPysaml2Cache
from . import filters
from .base import BaseDAO

logger: logging.Logger = logging.getLogger(__name__)


class SAMLPysaml2CacheDAO(filters.FilterMixin, BaseDAO):
    search_filter: filters.SearchFilter = filters.saml_pysaml2_cache_search_filter

    def get_expired(self, expiration_ts: int) -> list[SAMLPysaml2Cache]:
        return (
            self.session.query(SAMLPysaml2Cache)
            .filter(SAMLPysaml2Cache.not_on_or_after < expiration_ts)
            .all()
        )

    def _search(self, **kwargs):
        search_filter = self.new_search_filter(**kwargs)
        return self.session.query(SAMLPysaml2Cache).filter(search_filter).all()

    def delete_encoded(self, name_id: str) -> None:
        filter_ = SAMLPysaml2Cache.name_id == name_id
        self.session.query(SAMLPysaml2Cache).filter(filter_).delete()
        self.session.commit()
        logger.debug("Deleted from pysaml cache %s", name_id)

    def delete(self, name_id: NameID) -> None:
        self.delete_encoded(code(name_id))

    def get_identity(
        self,
        name_id: NameID,
        entities: str | None = None,
        check_not_on_or_after: bool = True,
    ):
        if not entities:
            try:
                cni: str = code(name_id)
                entities = (
                    self.session.query(SAMLPysaml2Cache)
                    .filter(SAMLPysaml2Cache.name_id == cni)
                    .all()
                )
            except Exception as e:
                logger.exception(e)
                return {}, []

        if not entities:
            return {}, []

        res = {}
        oldees = []
        for entity in entities:
            try:
                info = self.get(name_id, entity.entity_id, check_not_on_or_after)
            except TooOld:
                oldees.append(entity.entity_id)
                continue

            if not info:
                oldees.append(entity.entity_id)
                continue

            for key, vals in info["ava"].items():
                try:
                    tmp = set(res[key]).union(set(vals))
                    res[key] = list(tmp)
                except KeyError:
                    res[key] = vals
        return res, oldees

    def get(self, name_id: NameID, entity_id: str, check_not_on_or_after: bool = True):
        cni = code(name_id)
        cache_entries = self._search(name_id=cni, entity_id=entity_id)
        if not cache_entries:
            return None
        timestamp = cache_entries[0].not_on_or_after
        info = cache_entries[0].info
        if not timestamp:
            return None

        info = json.loads(info).copy()
        if check_not_on_or_after and time_util.after(timestamp):
            raise TooOld(f"past {str(timestamp)}")

        if "name_id" in info and isinstance(info["name_id"], str):
            info["name_id"] = decode(info["name_id"])
        return info or None

    def set(
        self,
        name_id: NameID,
        entity_id: str,
        info: dict[str, Any],
        not_on_or_after: int = 0,
    ):
        info = dict(info)
        if "name_id" in info and not isinstance(info["name_id"], str):
            info["name_id"] = code(name_id)

        cni = code(name_id)

        if self.get(name_id, entity_id, False):
            search_filter = self.new_search_filter(name_id=cni, entity_id=entity_id)
            data = {
                'name_id': cni,
                'entity_id': entity_id,
                'info': json.dumps(obj=info),
                'not_on_or_after': not_on_or_after,
            }
            self.session.query(SAMLPysaml2Cache).filter(search_filter).update(
                data, synchronize_session='fetch'
            )
        else:
            self.session.add(
                SAMLPysaml2Cache(
                    name_id=str(cni),
                    entity_id=entity_id,
                    info=json.dumps(obj=info),
                    not_on_or_after=not_on_or_after,
                )
            )
        try:
            self.session.flush()
        except exc.IntegrityError:
            self.session.rollback()
            raise

    def reset(self, name_id: NameID, entity_id: str):
        logger.debug("Reset pysaml2 cache entry for %s", name_id)
        self.set(name_id, entity_id, {}, 0)

    def entities(self, name_id: NameID):
        cni = code(name_id)
        return [k.entity_id for k in self._search(name_id=cni)]

    def receivers(self, name_id: NameID):
        return self.entities(name_id)

    def active(self, name_id: NameID, entity_id: str):
        try:
            cni = code(name_id)
            entry = self._search(name_id=cni, entity_id=entity_id)[0]
        except IndexError:
            return False
        except Exception as e:
            logger.exception(e)
            return False

        if not entry.info:
            return False
        else:
            return time_util.not_on_or_after(entry.not_on_or_after)

    def subjects(self) -> list[NameID]:
        return [decode(c) for c in self._search()]
