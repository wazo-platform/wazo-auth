# Copyright 2022-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time

from hamcrest import assert_that, is_
from saml2.saml import NameID

from .helpers import base, fixtures


@base.use_asset('database')
class TestSAMLPysaml2Cache(base.DAOTestCase):

    NAME_ID: NameID = NameID(
        text='alice@test.idp.com',
        format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    )
    BOB_NAME_ID: NameID = NameID(
        text='bob@test.idp.com',
        format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    )

    @fixtures.db.saml_pysaml2_cache(NAME_ID)
    def test_get_identity(self, fixture) -> None:
        res, oldees = self._saml_pysaml2_cache_dao.get_identity(self.NAME_ID)
        assert_that(res, is_(fixture['info']['ava']))
        assert_that(oldees, is_([]))

    def test_set(self) -> None:
        entry = {
            'name_id': self.NAME_ID,
            'entity_id': 'https://test.idp.com/saml2/idp/id-1',
            'info': {
                'ava': {
                    'givenName': ['Alice'],
                    'surname': ['Test'],
                    'name': ['alice@test.idp.com'],
                },
                'name_id': '2=urn%3Aoasis%3Anames%3Atc%3ASAML%3A1.1%3Anameid-format%3AemailAddress'
                + ',4=alice%40test.idp.com',
                'came_from': 'bldKO8ntPi1zLbHVgBwYuw',
                'authn_info': [
                    (
                        'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
                        [],
                        '2024-09-16T09:18:09.886Z',
                    )
                ],
                'session_index': '_4564564-3453df-3456345792a',
            },
            'not_on_or_after': int(time.time()) + 3600,
        }

        self._saml_pysaml2_cache_dao.set(**entry)
        res, oldees = self._saml_pysaml2_cache_dao.get_identity(self.NAME_ID)

        assert_that(res, is_(entry['info']['ava']))

    @fixtures.db.saml_pysaml2_cache(NAME_ID)
    def test_delete(self, _) -> None:
        self._saml_pysaml2_cache_dao.delete(self.NAME_ID)
        res, oldees = self._saml_pysaml2_cache_dao.get_identity(self.NAME_ID)

        assert_that(res, is_({}))
        assert_that(oldees, is_([]))

    @fixtures.db.saml_pysaml2_cache(NAME_ID)
    def test_reset(self, fixture) -> None:
        self._saml_pysaml2_cache_dao.reset(self.NAME_ID, fixture['entity_id'])
        res, oldees = self._saml_pysaml2_cache_dao.get_identity(self.NAME_ID)
        assert_that(res, is_({}))
        assert_that(oldees, is_([fixture['entity_id']]))

    @fixtures.db.saml_pysaml2_cache(NAME_ID)
    def test_entities(self, fixture) -> None:
        entities = self._saml_pysaml2_cache_dao.entities(self.NAME_ID)
        assert_that(entities, is_([fixture['entity_id']]))

    @fixtures.db.saml_pysaml2_cache(NAME_ID)
    def test_active(self, alice) -> None:
        active = self._saml_pysaml2_cache_dao.active(self.NAME_ID, alice['entity_id'])
        assert_that(active, is_(True))

    @fixtures.db.saml_pysaml2_cache(
        BOB_NAME_ID, not_on_or_after=int(time.time()) - 3600
    )
    def test_inactive(self, bob) -> None:
        active = self._saml_pysaml2_cache_dao.active(self.BOB_NAME_ID, bob['entity_id'])
        assert_that(active, is_(False))
