# Copyright 2015-2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import ldap
import xivo_dao

from ldap.filter import escape_filter_chars
from ldap.dn import escape_dn_chars
from wazo_auth import BaseAuthenticationBackend

from xivo_dao.resources.user.dao import find_by
from xivo_dao.helpers.db_utils import session_scope

logger = logging.getLogger(__name__)


class LDAPUser(BaseAuthenticationBackend):
    def load(self, dependencies):
        super().load(dependencies)
        config = dependencies['config']
        xivo_dao.init_db(config['confd_db_uri'])
        self.config = config['ldap']
        self.uri = self.config['uri']
        self.bind_dn = self.config.get('bind_dn', '')
        self.bind_password = self.config.get('bind_password', '')
        self.bind_anonymous = self.config.get('bind_anonymous', False)
        self.user_base_dn = self.config['user_base_dn']
        self.user_login_attribute = self.config['user_login_attribute']
        self.user_email_attribute = self.config.get('user_email_attribute', 'mail')

    def get_acls(self, login, args):
        acl = args.get('acl', [])
        return acl

    def get_metadata(self, username, args):
        metadata = super().get_metadata(username, args)
        user_data = {
            'auth_id': args['pbx_user_uuid'],  # TODO the auth id should be the ldap id
            'pbx_user_uuid': args['pbx_user_uuid'],
        }
        metadata.update(user_data)
        return metadata

    def verify_password(self, username, password, args):
        try:
            xivo_ldap = _XivoLDAP(self.uri)

            if self.bind_anonymous or (self.bind_dn and self.bind_password):
                if xivo_ldap.perform_bind(self.bind_dn, self.bind_password):
                    user_dn = self._perform_search_dn(xivo_ldap, username)
                else:
                    return False
            else:
                user_dn = self._build_dn_with_config(username)

            if not user_dn or not xivo_ldap.perform_bind(user_dn, password):
                return False

            user_email = self._get_user_ldap_email(xivo_ldap, user_dn)
            if not user_email:
                return False

        except ldap.SERVER_DOWN:
            logger.warning('LDAP : SERVER not responding on %s', self.uri)
            return False
        except ldap.LDAPError as exc:
            logger.exception('ldap.LDAPError (%r, %r)', self.config, exc)
            return False

        pbx_user_uuid = self._get_pbx_user_uuid_by_ldap_attribute(user_email)
        if not pbx_user_uuid:
            return False

        args['pbx_user_uuid'] = pbx_user_uuid

        return True

    @staticmethod
    def should_be_loaded(config):
        return bool(config.get('ldap', False))

    def _get_pbx_user_uuid_by_ldap_attribute(self, user_email):
        with session_scope():
            xivo_user = find_by(email=user_email)
            if not xivo_user:
                logger.warning(
                    '%s does not have an email associated with a PBX user', user_email
                )
                return xivo_user
            return xivo_user.uuid

    def _build_dn_with_config(self, login):
        login_esc = escape_dn_chars(login)
        return '{}={},{}'.format(
            self.user_login_attribute, login_esc, self.user_base_dn
        )

    def _get_user_ldap_email(self, xivo_ldap, user_dn):
        _, obj = xivo_ldap.perform_search(
            user_dn, ldap.SCOPE_BASE, attrlist=[self.user_email_attribute]
        )
        email = obj.get(self.user_email_attribute, None)
        email = email[0] if isinstance(email, list) else email
        if not email:
            logger.debug('LDAP : No email found for the user DN: %s', user_dn)
        return email.decode('utf-8')

    def _perform_search_dn(self, xivo_ldap, username):
        username_esc = escape_filter_chars(username)
        filterstr = '{}={}'.format(self.user_login_attribute, username_esc)
        dn, _ = xivo_ldap.perform_search(
            self.user_base_dn, ldap.SCOPE_SUBTREE, filterstr=filterstr, attrlist=['']
        )
        if not dn:
            logger.debug(
                'LDAP : No user DN for user_base dn: %s and filterstr: %s',
                self.user_base_dn,
                filterstr,
            )
        return dn


class _XivoLDAP:
    def __init__(self, uri):
        self.uri = uri
        self.ldapobj = self._create_ldap_obj(self.uri)

    def _create_ldap_obj(self, uri):
        ldapobj = ldap.initialize(uri)
        ldapobj.set_option(ldap.OPT_REFERRALS, 0)
        ldapobj.set_option(ldap.OPT_NETWORK_TIMEOUT, 2)
        ldapobj.set_option(ldap.OPT_TIMEOUT, 2)
        return ldapobj

    def perform_bind(self, username, password):
        try:
            self.ldapobj.simple_bind_s(username, password)
            logger.debug('LDAP : simple bind done with %s on %s', username, self.uri)
        except ldap.INVALID_CREDENTIALS:
            logger.info(
                'LDAP : simple bind failed with %s on %s : invalid credentials!',
                username,
                self.uri,
            )
            return False

        return True

    def perform_search(self, base, scope, filterstr='(objectClass=*)', attrlist=None):
        try:
            results = self.ldapobj.search_ext_s(
                base, scope, filterstr=filterstr, attrlist=attrlist, sizelimit=1
            )
        except ldap.SIZELIMIT_EXCEEDED:
            logger.debug(
                'LDAP : More than 1 result for base: %s and filterstr: %s',
                base,
                filterstr,
            )
            return None, None

        if not results:
            logger.debug(
                'LDAP : No result found for base: %s and filterstr: %s', base, filterstr
            )
            return None, None

        return results[0]
