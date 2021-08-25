# Copyright 2016-2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import ldap
import requests
import time

from collections import namedtuple
from ldap.modlist import addModlist
from hamcrest import assert_that, has_entries, calling, raises

from .helpers import base

Contact = namedtuple('Contact', ['cn', 'uid', 'password', 'mail', 'login_attribute'])


class LDAPHelper:

    BASE_DN = 'dc=wazo-auth,dc=wazo,dc=community'
    ADMIN_DN = 'cn=admin,{}'.format(BASE_DN)
    ADMIN_PASSWORD = 'wazopassword'
    PEOPLE_DN = 'ou=people,{}'.format(BASE_DN)
    QUEBEC_DN = 'ou=quebec,{}'.format(PEOPLE_DN)
    OU_DN = {'people': PEOPLE_DN, 'quebec': QUEBEC_DN}

    def __init__(self, ldap_uri):
        self._ldap_obj = ldap.initialize(ldap_uri)
        self._ldap_obj.simple_bind_s(self.ADMIN_DN, self.ADMIN_PASSWORD)

    def add_contact(self, contact, ou):
        dn = 'cn={},{}'.format(contact.cn, self.OU_DN[ou])
        modlist = addModlist(
            {
                'objectClass': [b'inetOrgPerson'],
                'cn': [contact.cn.encode('utf-8')],
                'sn': [contact.cn.encode('utf-8')],
                'uid': [contact.uid.encode('utf-8')],
                'userPassword': [contact.password.encode('utf-8')],
                'mail': [contact.mail.encode('utf-8')],
            }
        )

        self._ldap_obj.add_s(dn, modlist)

    def add_ou(self):
        modlist = addModlist(
            {'objectClass': [b'organizationalUnit'], 'ou': [b'people']}
        )
        self._ldap_obj.add_s(self.PEOPLE_DN, modlist)
        modlist = addModlist(
            {'objectClass': [b'organizationalUnit'], 'ou': [b'quebec']}
        )
        self._ldap_obj.add_s(self.QUEBEC_DN, modlist)


def add_contacts(contacts, ldap_uri):
    for _ in range(10):
        try:
            helper = LDAPHelper(ldap_uri)
            break
        except ldap.SERVER_DOWN:
            time.sleep(1)
    else:
        raise Exception('could not add contacts: LDAP server is down')

    helper.add_ou()
    helper.add_contact(Contact('wazo_auth', 'wazo_auth', 'S3cr$t', '', 'cn'), 'people')
    for contact in contacts:
        helper.add_contact(contact, 'quebec')


class _BaseLDAPTestCase(base.BaseIntegrationTest):

    username = 'admin'
    password = 's3cre7'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        ldap_host = '127.0.0.1'
        ldap_port = cls.asset_cls.service_port(389, 'slapd')
        ldap_uri = f'ldap://{ldap_host}:{ldap_port}'
        add_contacts(cls.CONTACTS, ldap_uri)


class LDAPIntegrationTest(_BaseLDAPTestCase):
    asset_cls = base.LDAPAssetLaunchingTestCase


class LDAPAnonymousIntegrationTest(_BaseLDAPTestCase):
    asset_cls = base.LDAPAnonymousAssetLaunchingTestCase


class LDAPServiceUserIntegrationTest(_BaseLDAPTestCase):
    asset_cls = base.LDAPServiceUserAssetLaunchingTestCase


@base.use_asset('ldap')
class TestLDAP(LDAPIntegrationTest):
    CONTACTS = [
        Contact(
            'Alice Wonderland',
            'awonderland',
            'awonderland_password',
            'awonderland@wazo-auth.com',
            'cn',
        )
    ]

    def test_ldap_authentication(self):
        response = self._post_token(
            'Alice Wonderland', 'awonderland_password', backend='ldap_user'
        )
        assert_that(response, has_entries(metadata=has_entries(pbx_user_uuid='1')))

    def test_ldap_authentication_fail_when_wrong_password(self):
        args = ('Alice Wonderland', 'wrong_password')
        assert_that(
            calling(self._post_token).with_args(*args, backend='ldap_user'),
            raises(requests.HTTPError, pattern='401'),
        )


@base.use_asset('ldap_anonymous')
class TestLDAPAnonymous(LDAPAnonymousIntegrationTest):
    CONTACTS = [
        Contact(
            'Alice Wonderland',
            'awonderland',
            'awonderland_password',
            'awonderland@wazo-auth.com',
            'mail',
        )
    ]

    def test_ldap_authentication(self):
        response = self._post_token(
            'awonderland@wazo-auth.com', 'awonderland_password', backend='ldap_user'
        )
        assert_that(response, has_entries(metadata=has_entries(pbx_user_uuid='1')))

    def test_ldap_authentication_fail_when_wrong_password(self):
        args = ('awonderland@wazo-auth.com', 'wrong_password')
        assert_that(
            calling(self._post_token).with_args(*args, backend='ldap_user'),
            raises(requests.HTTPError, pattern='401'),
        )


@base.use_asset('ldap_service_user')
class TestLDAPServiceUser(LDAPServiceUserIntegrationTest):
    CONTACTS = [
        Contact(
            'Alice Wonderland',
            'awonderland',
            'awonderland_password',
            'awonderland@wazo-auth.com',
            'uid',
        )
    ]

    def test_ldap_authentication(self):
        response = self._post_token(
            'awonderland', 'awonderland_password', backend='ldap_user'
        )
        assert_that(response, has_entries(metadata=has_entries(pbx_user_uuid='1')))

    def test_ldap_authentication_fail_when_wrong_password(self):
        args = ('awonderland', 'wrong_password')
        assert_that(
            calling(self._post_token).with_args(*args, backend='ldap_user'),
            raises(requests.HTTPError, pattern='401'),
        )
