# -*- coding: utf-8 -*-
# Copyright 2016-2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import docker as docker_client
import os
import subprocess
import ldap
import time

from collections import namedtuple
from contextlib import contextmanager
from ldap.modlist import addModlist
from hamcrest import assert_that
from hamcrest import equal_to

from .helpers.base import BaseTestCase

Contact = namedtuple('Contact', ['cn', 'uid', 'password', 'mail', 'login_attribute'])


@contextmanager
def cd(newdir):
    prevdir = os.getcwd()
    os.chdir(os.path.expanduser(newdir))
    try:
        yield
    finally:
        os.chdir(prevdir)


def _run_cmd(cmd, stderr=True):
    with open(os.devnull, "w") as null:
        stderr = subprocess.STDOUT if stderr else null
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr)
        out, _ = process.communicate()
    return out


class LDAPHelper(object):

    BASE_DN = 'dc=wazo-auth,dc=wazo,dc=community'
    ADMIN_DN = 'cn=admin,{}'.format(BASE_DN)
    ADMIN_PASSWORD = 'wazopassword'
    PEOPLE_DN = 'ou=people,{}'.format(BASE_DN)
    QUEBEC_DN = 'ou=quebec,{}'.format(PEOPLE_DN)
    OU_DN = {'people': PEOPLE_DN,
             'quebec': QUEBEC_DN}

    def __init__(self, ldap_uri):
        self._ldap_obj = ldap.initialize(ldap_uri)
        self._ldap_obj.simple_bind_s(self.ADMIN_DN, self.ADMIN_PASSWORD)

    def add_contact(self, contact, ou):
        dn = 'cn={},{}'.format(contact.cn, self.OU_DN[ou])
        modlist = addModlist({
            'objectClass': ['inetOrgPerson'],
            'cn': [contact.cn],
            'sn': [contact.cn],
            'uid': [contact.uid],
            'userPassword': [contact.password],
            'mail': [contact.mail]
        })

        self._ldap_obj.add_s(dn, modlist)

    def add_ou(self):
        modlist = addModlist({
            'objectClass': ['organizationalUnit'],
            'ou': ['people'],
        })
        self._ldap_obj.add_s(self.PEOPLE_DN, modlist)
        modlist = addModlist({
            'objectClass': ['organizationalUnit'],
            'ou': ['quebec'],
        })
        self._ldap_obj.add_s(self.QUEBEC_DN, modlist)


def add_contacts(contacts, ldap_uri):
    for _ in xrange(10):
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


class _BaseLDAPTestCase(BaseTestCase):

    @classmethod
    def setUpClass(cls):
        super(_BaseLDAPTestCase, cls).setUpClass()
        port = cls.service_port(389, 'slapd')
        ldap_uri = 'ldap://localhost:{port}'.format(port=port)

        try:
            add_contacts(cls.CONTACTS, ldap_uri)
        except Exception:
            super(_BaseLDAPTestCase, cls).tearDownClass()
            raise

    @classmethod
    def service_port(cls, internal_port, service_name=None):
        if not service_name:
            service_name = cls.service

        docker = docker_client.from_env().api
        result = docker.port(cls._container_id(service_name), internal_port)

        if not result:
            raise Exception('No such port: {} {}'.format(service_name, internal_port))

        return int(result[0]['HostPort'])


class TestLDAP(_BaseLDAPTestCase):

    asset = 'ldap'

    CONTACTS = [
        Contact('Alice Wonderland', 'awonderland', 'awonderland_password', 'awonderland@wazo-auth.com', 'cn'),
    ]

    def test_ldap_authentication(self):
        response = self._post_token('Alice Wonderland', 'awonderland_password', backend='ldap_user')

        xivo_user_uuid = response['xivo_user_uuid']
        assert_that(xivo_user_uuid, equal_to('1'))

    def test_ldap_authentication_fail_when_wrong_password(self):
        self._post_token_with_expected_exception('Alice Wonderland', 'wrong_password', backend='ldap_user', status_code=401)


class TestLDAPAnonymous(_BaseLDAPTestCase):

    asset = 'ldap_anonymous'

    CONTACTS = [
        Contact('Alice Wonderland', 'awonderland', 'awonderland_password', 'awonderland@wazo-auth.com', 'mail'),
    ]

    def test_ldap_authentication(self):
        response = self._post_token('awonderland@wazo-auth.com', 'awonderland_password', backend='ldap_user')

        xivo_user_uuid = response['xivo_user_uuid']
        assert_that(xivo_user_uuid, equal_to('1'))

    def test_ldap_authentication_fail_when_wrong_password(self):
        self._post_token_with_expected_exception(
            'awonderland@wazo-auth.com', 'wrong_password', backend='ldap_user', status_code=401)


class TestLDAPServiceUser(_BaseLDAPTestCase):

    asset = 'ldap_service_user'

    CONTACTS = [
        Contact('Alice Wonderland', 'awonderland', 'awonderland_password', 'awonderland@wazo-auth.com', 'uid'),
    ]

    def test_ldap_authentication(self):
        response = self._post_token('awonderland', 'awonderland_password', backend='ldap_user')

        xivo_user_uuid = response['xivo_user_uuid']
        assert_that(xivo_user_uuid, equal_to('1'))

    def test_ldap_authentication_fail_when_wrong_password(self):
        self._post_token_with_expected_exception(
            'awonderland', 'wrong_password', backend='ldap_user', status_code=401)
