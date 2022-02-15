# Copyright 2016-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import ldap
import requests
import time

from collections import namedtuple
from ldap.modlist import addModlist
from hamcrest import assert_that, has_entries, calling, raises

from .helpers import base, fixtures

Contact = namedtuple('Contact', ['cn', 'uid', 'password', 'mail', 'login_attribute'])

TENANT_1_UUID = '2ec55cd6-c465-47a9-922f-569b404c48b8'
TENANT_2_UUID = '402f2ee0-2af9-4b87-80ce-9d9e94f620e5'


class LDAPHelper:

    BASE_DN = 'dc=wazo-auth,dc=wazo,dc=community'
    ADMIN_DN = 'cn=admin,{}'.format(BASE_DN)
    ADMIN_PASSWORD = 'wazopassword'
    PEOPLE_DN = 'ou=people,{}'.format(BASE_DN)
    QUEBEC_DN = 'ou=quebec,{}'.format(PEOPLE_DN)
    OU_DN = {'people': PEOPLE_DN, 'quebec': QUEBEC_DN}
    setup_ran = False

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

    def add_contact_without_email(self, contact, ou):
        dn = 'cn={},{}'.format(contact.cn, self.OU_DN[ou])
        modlist = addModlist(
            {
                'objectClass': [b'inetOrgPerson'],
                'cn': [contact.cn.encode('utf-8')],
                'sn': [contact.cn.encode('utf-8')],
                'uid': [contact.uid.encode('utf-8')],
                'userPassword': [contact.password.encode('utf-8')],
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


class BaseLDAPIntegrationTest(base.BaseIntegrationTest):

    asset_cls = base.LDAPAssetLaunchingTestCase
    username = 'admin'
    password = 's3cre7'

    CONTACTS = [
        Contact(
            'Alice Wonderland',
            'awonderland',
            'awonderland_password',
            'awonderland@wazo-auth.com',
            'cn',
        ),
        Contact(
            'Humpty Dumpty',
            'humptydumpty',
            'humptydumpty_password',
            None,
            'uid',
        ),
        Contact(
            'Lewis Carroll',
            'lewiscarroll',
            'lewiscarroll_password',
            'lewiscarroll@wazo-auth.com',
            'mail',
        ),
    ]

    @classmethod
    def add_contacts(cls, contacts, ldap_helper):
        ldap_helper.add_ou()
        ldap_helper.add_contact(
            Contact('wazo_auth', 'wazo_auth', 'S3cr$t', '', 'cn'), 'people'
        )
        for contact in contacts:
            if not contact.mail:
                ldap_helper.add_contact_without_email(contact, 'quebec')
            else:
                ldap_helper.add_contact(contact, 'quebec')

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        ldap_host = '127.0.0.1'
        ldap_port = cls.asset_cls.service_port(389, 'slapd')
        ldap_uri = f'ldap://{ldap_host}:{ldap_port}'

        for _ in range(10):
            try:
                helper = LDAPHelper(ldap_uri)
                break
            except ldap.SERVER_DOWN:
                time.sleep(1)
        else:
            raise Exception('could not add contacts: LDAP server is down')
        if not LDAPHelper.setup_ran:
            cls.add_contacts(cls.CONTACTS, helper)
            LDAPHelper.setup_ran = True


@base.use_asset('ldap')
class TestLDAP(BaseLDAPIntegrationTest):
    def setUp(self):
        ldap_config = self.client.ldap_config.update(
            {
                'host': 'slapd',
                'port': 389,
                'user_base_dn': 'ou=quebec,ou=people,dc=wazo-auth,dc=wazo,dc=community',
                'user_login_attribute': 'cn',
                'user_email_attribute': 'mail',
            },
            tenant_uuid=self.top_tenant_uuid,
        )
        self.addCleanup(self.client.ldap_config.delete, ldap_config['tenant_uuid'])

    @fixtures.http.user(email_address='awonderland@wazo-auth.com')
    def test_ldap_authentication(self, user):
        response = self._post_token(
            'Alice Wonderland',
            'awonderland_password',
            backend='ldap_user',
            tenant_id=self.top_tenant_uuid,
        )
        assert_that(
            response, has_entries(metadata=has_entries(pbx_user_uuid=user['uuid']))
        )

    @fixtures.http.tenant(uuid=TENANT_1_UUID)
    @fixtures.http.user(
        email_address='lewiscarroll@wazo-auth.com', tenant_uuid=TENANT_1_UUID
    )
    @fixtures.http.tenant(uuid=TENANT_2_UUID)
    @fixtures.http.ldap_config(
        tenant_uuid=TENANT_2_UUID,
        host='slapd',
        port=389,
        bind_dn='cn=wazo_auth,ou=people,dc=wazo-auth,dc=wazo,dc=community',
        bind_password='S3cr$t',
        user_base_dn='dc=wazo-auth,dc=wazo,dc=community',
        user_login_attribute='mail',
        user_email_attribute='mail',
    )
    def test_ldap_authentication_multi_tenant(self, _, __, tenant2, ___):
        args = ('lewiscarroll@wazo-auth.com', 'lewiscarroll_password')
        assert_that(
            calling(self._post_token).with_args(
                *args, backend='ldap_user', tenant_id=tenant2['slug']
            ),
            raises(requests.HTTPError, pattern='401'),
        )

    @fixtures.http.user(email_address='awonderland@wazo-auth.com')
    def test_ldap_authentication_fail_when_wrong_password(self, _):
        args = ('Alice Wonderland', 'wrong_password')
        assert_that(
            calling(self._post_token).with_args(
                *args, backend='ldap_user', tenant_id=self.top_tenant_uuid
            ),
            raises(requests.HTTPError, pattern='401'),
        )

    @fixtures.http.user(email_address='humptydumpty@wazo-auth.com')
    def test_ldap_authentication_fails_when_no_email_in_ldap(self, _):
        args = ('Humpty Dumpty', 'humptydumpty_password')
        assert_that(
            calling(self._post_token).with_args(
                *args, backend='ldap_user', tenant_id=self.top_tenant_uuid
            ),
            raises(requests.HTTPError, pattern='401'),
        )

    @fixtures.http.user(email_address=None)
    def test_ldap_authentication_fails_when_no_email_in_user(self, _):
        args = ('Lewis Carroll', 'lewiscarroll_password')
        assert_that(
            calling(self._post_token).with_args(
                *args, backend='ldap_user', tenant_id=self.top_tenant_uuid
            ),
            raises(requests.HTTPError, pattern='401'),
        )


@base.use_asset('ldap')
class TestLDAPServiceUser(BaseLDAPIntegrationTest):
    def setUp(self):
        ldap_config = self.client.ldap_config.update(
            {
                'host': 'slapd',
                'port': 389,
                'bind_dn': 'cn=wazo_auth,ou=people,dc=wazo-auth,dc=wazo,dc=community',
                'bind_password': 'S3cr$t',
                'user_base_dn': 'dc=wazo-auth,dc=wazo,dc=community',
                'user_login_attribute': 'uid',
                'user_email_attribute': 'mail',
            },
            tenant_uuid=self.top_tenant_uuid,
        )
        self.addCleanup(self.client.ldap_config.delete, ldap_config['tenant_uuid'])

    @fixtures.http.user(email_address='awonderland@wazo-auth.com')
    def test_ldap_authentication(self, user):
        response = self._post_token(
            'awonderland',
            'awonderland_password',
            backend='ldap_user',
            tenant_id=self.top_tenant_uuid,
        )
        assert_that(
            response, has_entries(metadata=has_entries(pbx_user_uuid=user['uuid']))
        )

    @fixtures.http.tenant(uuid=TENANT_1_UUID)
    @fixtures.http.user(
        email_address='lewiscarroll@wazo-auth.com', tenant_uuid=TENANT_1_UUID
    )
    @fixtures.http.tenant(uuid=TENANT_2_UUID)
    @fixtures.http.ldap_config(
        tenant_uuid=TENANT_2_UUID,
        host='slapd',
        port=389,
        bind_dn='cn=wazo_auth,ou=people,dc=wazo-auth,dc=wazo,dc=community',
        bind_password='S3cr$t',
        user_base_dn='dc=wazo-auth,dc=wazo,dc=community',
        user_login_attribute='mail',
        user_email_attribute='mail',
    )
    def test_ldap_authentication_multi_tenant(self, _, __, tenant2, ___):
        args = ('lewiscarroll@wazo-auth.com', 'lewiscarroll_password')
        assert_that(
            calling(self._post_token).with_args(
                *args, backend='ldap_user', tenant_id=tenant2['slug']
            ),
            raises(requests.HTTPError, pattern='401'),
        )

    @fixtures.http.user(email_address='awonderland@wazo-auth.com')
    def test_ldap_authentication_fail_when_wrong_password(self, _):
        args = ('awonderland', 'wrong_password')
        assert_that(
            calling(self._post_token).with_args(
                *args, backend='ldap_user', tenant_id=self.top_tenant_uuid
            ),
            raises(requests.HTTPError, pattern='401'),
        )

    @fixtures.http.user(email_address='humptydumpty@wazo-auth.com')
    def test_ldap_authentication_fails_when_no_email_in_ldap(self, _):
        args = ('humptydumpty', 'humptydumpty_password')
        assert_that(
            calling(self._post_token).with_args(
                *args, backend='ldap_user', tenant_id=self.top_tenant_uuid
            ),
            raises(requests.HTTPError, pattern='401'),
        )

    @fixtures.http.user(email_address=None)
    def test_ldap_authentication_fails_when_no_email_in_user(self, _):
        args = ('lewiscarroll', 'lewiscarroll_password')
        assert_that(
            calling(self._post_token).with_args(
                *args, backend='ldap_user', tenant_id=self.top_tenant_uuid
            ),
            raises(requests.HTTPError, pattern='401'),
        )
