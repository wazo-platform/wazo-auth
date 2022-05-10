# Copyright 2016-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import ldap
import requests
import time

from collections import namedtuple
from ldap.modlist import addModlist
from hamcrest import assert_that, has_entries, calling, raises

from .helpers import base, fixtures

Contact = namedtuple(
    'Contact',
    [
        'cn',
        'uid',
        'password',
        'mail',
        'login_attribute',
        'employee_type',
        'search_only',
    ],
)

TENANT_1_UUID = '2ec55cd6-c465-47a9-922f-569b404c48b8'
TENANT_2_UUID = '402f2ee0-2af9-4b87-80ce-9d9e94f620e5'
LDAP_PORT = 1389


class LDAPHelper:

    BASE_DN = 'dc=wazo-auth,dc=wazo,dc=community'
    ADMIN_DN = 'cn=admin,{}'.format(BASE_DN)
    ADMIN_PASSWORD = 'wazopassword'
    PEOPLE_DN = 'ou=people,{}'.format(BASE_DN)
    QUEBEC_DN = 'ou=quebec,{}'.format(PEOPLE_DN)
    OU_DN = {'people': PEOPLE_DN, 'quebec': QUEBEC_DN}
    CONFIG_DN = 'cn=config'
    CONFIG_DATABASE_DN = 'olcDatabase={{2}}mdb,{}'.format(CONFIG_DN)
    CONFIG_ADMIN_DN = 'cn=admin,{}'.format(CONFIG_DN)
    CONFIG_ADMIN_PASSWORD = 'configpassword'
    setup_ran = False

    def __init__(self, ldap_uri):
        self._ldap_obj = ldap.initialize(ldap_uri)
        self._ldap_obj.simple_bind_s(self.ADMIN_DN, self.ADMIN_PASSWORD)
        self._ldap_admin_obj = ldap.initialize(ldap_uri)
        self._ldap_admin_obj.simple_bind_s(
            self.CONFIG_ADMIN_DN, self.CONFIG_ADMIN_PASSWORD
        )

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
                'employeeType': [contact.employee_type.encode('utf-8')],
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
                'employeeType': [contact.employee_type.encode('utf-8')],
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

    def add_acl(self, contact, affected_ou, acl):
        _, old_config = self._ldap_admin_obj.search_ext_s(
            self.CONFIG_DATABASE_DN, ldap.SCOPE_SUBTREE
        )[0]

        new_config = old_config.copy()
        ou = self.OU_DN[affected_ou]
        user_dn = 'cn={},{}'.format(contact.cn, ou)

        new_config['olcAccess'] = new_config.get('olcAccess', [])
        acls = new_config['olcAccess']
        acls.insert(
            0, f'to attrs=mail by dn.exact="{user_dn}" {acl} by * write'.encode('utf-8')
        )
        acls.append('to * by self read by users read by * read'.encode('utf-8'))
        self._ldap_admin_obj.add_s(self.CONFIG_DATABASE_DN, addModlist(new_config))


@base.use_asset('base')
class BaseLDAPIntegrationTest(base.BaseIntegrationTest):

    asset_cls = base.APIAssetLaunchingTestCase
    username = 'admin'
    password = 's3cre7'

    CONTACTS = [
        Contact(
            cn='Alice Wonderland',
            uid='awonderland',
            password='awonderland_password',
            mail='awonderland@wazo-auth.com',
            login_attribute='cn',
            employee_type='human',
            search_only=False,
        ),
        Contact(
            cn='Humpty Dumpty',
            uid='humptydumpty',
            password='humptydumpty_password',
            mail=None,
            login_attribute='uid',
            employee_type='human',
            search_only=False,
        ),
        Contact(
            cn='Lewis Carroll',
            uid='lewiscarroll',
            password='lewiscarroll_password',
            mail='lewiscarroll@wazo-auth.com',
            login_attribute='mail',
            employee_type='human',
            search_only=False,
        ),
        Contact(
            cn='The Cheshire Cat',
            uid='cheshirecat',
            password='cheshirecat_password',
            mail='cheshirecat@wazo-auth.com',
            login_attribute='mail',
            employee_type='animal',
            search_only=False,
        ),
        Contact(
            cn='The White Queen',
            uid='whitequeen',
            password='whitequeen_password',
            mail='whitequeen@wazo-auth.com',
            login_attribute='mail',
            employee_type='human',
            search_only=True,
        ),
    ]

    @classmethod
    def add_contacts(cls, contacts, ldap_helper):
        ldap_helper.add_ou()
        ldap_helper.add_contact(
            Contact('wazo_auth', 'wazo_auth', 'S3cr$t', '', 'cn', 'service', False),
            'people',
        )
        for contact in contacts:
            if not contact.mail:
                ldap_helper.add_contact_without_email(contact, 'quebec')
            else:
                ldap_helper.add_contact(contact, 'quebec')

            if contact.search_only:
                ldap_helper.add_acl(contact, 'quebec', 'search')

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        ldap_host = '127.0.0.1'
        ldap_port = cls.asset_cls.service_port(LDAP_PORT, 'slapd')
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


@base.use_asset('base')
class TestLDAP(BaseLDAPIntegrationTest):
    def setUp(self):
        ldap_config = self.client.ldap_config.update(
            {
                'host': 'slapd',
                'port': LDAP_PORT,
                'user_base_dn': 'ou=quebec,ou=people,dc=wazo-auth,dc=wazo,dc=community',
                'user_login_attribute': 'cn',
                'user_email_attribute': 'mail',
            },
            tenant_uuid=self.top_tenant_uuid,
        )
        self.addCleanup(self.client.ldap_config.delete, ldap_config['tenant_uuid'])

    @fixtures.http.tenant(
        uuid=TENANT_1_UUID,
        slug='mytenant',
        domain_names=['wazo.community', 'cust-42.myclients.com'],
    )
    @fixtures.http.user(
        email_address='awonderland@wazo-auth.com', tenant_uuid=TENANT_1_UUID
    )
    @fixtures.http.ldap_config(
        tenant_uuid=TENANT_1_UUID,
        host='slapd',
        port=LDAP_PORT,
        user_base_dn='ou=quebec,ou=people,dc=wazo-auth,dc=wazo,dc=community',
        user_login_attribute='cn',
        user_email_attribute='mail',
    )
    def test_ldap_authentication_with_tenant_id_and_hostname(self, user):
        response = self._post_token(
            'Alice Wonderland',
            'awonderland_password',
            backend='ldap_user',
            tenant_id=tenant['uuid'],
        )
        assert_that(
            response, has_entries(metadata=has_entries(pbx_user_uuid=user['uuid']))
        )

        response = self._post_token(
            'Alice Wonderland',
            'awonderland_password',
            backend='ldap_user',
            tenant_id=tenant['slug'],
        )
        assert_that(
            response, has_entries(metadata=has_entries(pbx_user_uuid=user['uuid']))
        )

        response = self._post_token(
            'Alice Wonderland',
            'awonderland_password',
            backend='ldap_user',
            hostname='cust-42.myclients.com',
        )
        assert_that(
            response, has_entries(metadata=has_entries(pbx_user_uuid=user['uuid']))
        )

        args = (
            'Alice Wonderland',
            'awonderland_password',
        )

        assert_that(
            calling(self._post_token).with_args(
                *args,
                backend='ldap_user',
                tenant_id=tenant['uuid'],
                hostname='cust-42.myclients.com',
            ),
            raises(requests.HTTPError, pattern='400'),
        )

    @fixtures.http.user(email_address='whitequeen@wazo-auth.com')
    def test_ldap_authentication_user_cannot_read_ldap_email(self, _):
        args = [
            'The White Queen',
            'whitequeen_password',
        ]
        assert_that(
            calling(self._post_token).with_args(
                *args,
                backend='ldap_user',
                tenant_id=self.top_tenant_uuid,
            ),
            raises(requests.HTTPError, pattern='401'),
        )

    @fixtures.http.tenant(uuid=TENANT_1_UUID)
    @fixtures.http.user(
        email_address='lewiscarroll@wazo-auth.com', tenant_uuid=TENANT_1_UUID
    )
    @fixtures.http.tenant(uuid=TENANT_2_UUID)
    @fixtures.http.ldap_config(
        tenant_uuid=TENANT_2_UUID,
        host='slapd',
        port=LDAP_PORT,
        bind_dn='cn=wazo_auth,ou=people,dc=wazo-auth,dc=wazo,dc=community',
        bind_password='S3cr$t',
        user_base_dn='dc=wazo-auth,dc=wazo,dc=community',
        user_login_attribute='mail',
        user_email_attribute='mail',
    )
    def test_ldap_authentication_multi_tenant(self, _, __, tenant2, ___):
        args = ('Lewis Carroll', 'lewiscarroll_password')
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


@base.use_asset('base')
class TestLDAPServiceUser(BaseLDAPIntegrationTest):
    def setUp(self):
        ldap_config = self.client.ldap_config.update(
            {
                'host': 'slapd',
                'port': LDAP_PORT,
                'bind_dn': 'cn=wazo_auth,ou=people,dc=wazo-auth,dc=wazo,dc=community',
                'bind_password': 'S3cr$t',
                'user_base_dn': 'dc=wazo-auth,dc=wazo,dc=community',
                'user_login_attribute': 'uid',
                'user_email_attribute': 'mail',
                'search_filters': '(&({user_login_attribute}={username})(employeeType=human))',
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

    @fixtures.http.user(email_address='whitequeen@wazo-auth.com')
    def test_ldap_authentication_user_cannot_read_ldap_email(self, user):
        response = self._post_token(
            'whitequeen',
            'whitequeen_password',
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
        port=LDAP_PORT,
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

    @fixtures.http.user(email_address='cheshirecat@wazo-auth.com')
    def test_ldap_authentication_search_filter_does_not_match_employee_type(self, _):
        args = ('cheshirecat', 'cheshirecat_password')
        assert_that(
            calling(self._post_token).with_args(
                *args, backend='ldap_user', tenant_id=self.top_tenant_uuid
            ),
            raises(requests.HTTPError, pattern='401'),
        )


@base.use_asset('base')
class TestLDAPRefreshToken(BaseLDAPIntegrationTest):
    def setUp(self):
        ldap_config = self.client.ldap_config.update(
            {
                'host': 'slapd',
                'port': LDAP_PORT,
                'user_base_dn': 'ou=quebec,ou=people,dc=wazo-auth,dc=wazo,dc=community',
                'user_login_attribute': 'cn',
                'user_email_attribute': 'mail',
            },
            tenant_uuid=self.top_tenant_uuid,
        )
        self.addCleanup(self.client.ldap_config.delete, ldap_config['tenant_uuid'])

    @fixtures.http.user(email_address='awonderland@wazo-auth.com')
    def test_ldap_login_with_refresh_token(self, user):
        client_id = 'my-test'
        args = ('Alice Wonderland', 'awonderland_password')
        refresh_token = self._post_token(
            *args,
            backend='ldap_user',
            client_id=client_id,
            access_type='offline',
            tenant_id=self.top_tenant_uuid,
        )['refresh_token']

        response = self._post_token(
            None,
            None,
            backend='ldap_user',
            expiration=1,
            refresh_token=refresh_token,
            client_id=client_id,
            tenant_id=self.top_tenant_uuid,
        )
        assert_that(
            response, has_entries(metadata=has_entries(pbx_user_uuid=user['uuid']))
        )
