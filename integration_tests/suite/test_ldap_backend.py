# -*- coding: utf-8 -*-

# Copyright (C) 2015 Avencall
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import ldap
import time

from .test_http_interface import _BaseTestCase

from collections import namedtuple
from ldap.modlist import addModlist
from hamcrest import assert_that
from hamcrest import equal_to

Contact = namedtuple('Contact', ['firstname', 'lastname', 'uid', 'password'])


class LDAPHelper(object):

    ADMIN_DN = 'cn=admin,dc=xivo-auth,dc=xivo,dc=io'
    ADMIN_PASSWORD = 'xivopassword'
    BIND_DN_FORMAT = 'uid={username},dc=xivo-auth,dc=xivo,dc=io'
    LDAP_URI = 'ldap://localhost:3899'

    def __init__(self):
        self._ldap_obj = ldap.initialize(self.LDAP_URI)
        self._ldap_obj.simple_bind_s(self.ADMIN_DN, self.ADMIN_PASSWORD)

    def add_contact(self, contact):
        cn = '{} {}'.format(contact.firstname, contact.lastname)
        dn = self.BIND_DN_FORMAT.format(username=contact.uid)
        modlist = addModlist({
            'objectClass': ['inetOrgPerson'],
            'cn': [cn],
            'sn': [contact.lastname],
            'uid': [contact.uid],
            'userPassword': [contact.password],
        })

        self._ldap_obj.add_s(dn, modlist)


def add_contacts(contacts):
    for _ in xrange(10):
        try:
            helper = LDAPHelper()
            break
        except ldap.SERVER_DOWN:
            time.sleep(1)
    else:
        raise Exception('could not add contacts: LDAP server is down')

    for contact in contacts:
        helper.add_contact(contact)


class TestLDAP(_BaseTestCase):

    asset = 'ldap'

    CONTACTS = [
        Contact('Alice', 'Wonderland', 'awonderland', 'awonderland_password'),
    ]

    @classmethod
    def setUpClass(cls):
        super(TestLDAP, cls).setUpClass()

        try:
            add_contacts(cls.CONTACTS)
        except Exception:
            super(TestLDAP, cls).tearDownClass()
            raise

    def test_ldap_authentication(self):
        response = self._post_token('awonderland', 'awonderland_password', backend='ldap_user_voicemail')

        assert_that(response.status_code, equal_to(200))

        xivo_user_uuid = response.json()['data']['xivo_user_uuid']
        assert_that(xivo_user_uuid, equal_to('1'))

    def test_ldap_authentication_fail_when_wrong_password(self):
        response = self._post_token('awonderland', 'wrong_password', backend='ldap_user_voicemail')

        assert_that(response.status_code, equal_to(401))
