# Copyright 2015-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import ldap
import logging

from ldap.filter import escape_filter_chars
from ldap.dn import escape_dn_chars
from wazo_auth import BaseAuthenticationBackend

logger = logging.getLogger(__name__)


class LDAPUser(BaseAuthenticationBackend):
    def load(self, dependencies):
        super().load(dependencies)
        self._user_service = dependencies['user_service']
        self._group_service = dependencies['group_service']
        self._purposes = dependencies['purposes']
        self._ldap_service = dependencies['ldap_service']
        self._tenant_service = dependencies['tenant_service']

    def get_acl(self, login, args):
        backend_acl = args.get('acl', [])
        user_uuid = self._user_service.get_user_uuid_by_login(args['user_email'])
        group_acl = self._group_service.get_acl(user_uuid)
        user_acl = self._user_service.get_acl(user_uuid)
        return backend_acl + group_acl + user_acl

    def get_metadata(self, login, args):
        metadata = super().get_metadata(login, args)
        user_data = {
            'auth_id': args['pbx_user_uuid'],  # TODO the auth id should be the ldap id
            'pbx_user_uuid': args['pbx_user_uuid'],
        }
        metadata.update(user_data)
        user_uuid = self._user_service.get_user_uuid_by_login(args['user_email'])
        purpose = self._user_service.list_users(uuid=user_uuid)[0]['purpose']
        for plugin in self._purposes.get(purpose).metadata_plugins:
            metadata.update(plugin.get_token_metadata(args['user_email'], args))
        return metadata

    def verify_password(self, username, password, args):
        tenant = self._get_tenant(args['tenant_id'])  # TODO Add token POST schema validation

        config = self._get_ldap_config(tenant)
        if not config:
            return False

        try:
            wazo_ldap = _WazoLDAP(config['uri'])

            if config['bind_dn'] and config['bind_password']:
                if wazo_ldap.perform_bind(config['bind_dn'], config['bind_password']):
                    user_dn = self._perform_search_dn(wazo_ldap, username)
                else:
                    return False
            else:
                user_dn = self._build_dn_with_config(username)

            if not user_dn or not wazo_ldap.perform_bind(user_dn, password):
                return False

            user_email = self._get_user_ldap_email(wazo_ldap, user_dn)
            if not user_email:
                return False

        except ldap.SERVER_DOWN:
            logger.warning('LDAP : SERVER not responding on %s', config['uri'])
            return False
        except ldap.LDAPError as exc:
            logger.exception('ldap.LDAPError (%r, %r)', config, exc)
            return False

        pbx_user_uuid = self._get_user_uuid_by_ldap_attribute(user_email)
        if not pbx_user_uuid:
            return False

        args['pbx_user_uuid'] = pbx_user_uuid
        args['user_email'] = user_email

        return True

    def _build_uri(self, protocol_security, port, host):
        scheme = 'ldaps' if protocol_security == 'ldaps' else 'ldap'
        return f'{scheme}://{host}:{port}'

    def _get_ldap_config(self, tenant_uuid):
        config = self._ldap_service.get(tenant_uuid)
        config['uri'] = self._build_uri(
            config['protocol_security'],
            config['port'],
            config['host'],
        )
        return config

    def _get_tenant(self, tenant_id):
        return self._tenant_service.get_by_uuid_or_slug(None, tenant_id)

    def _get_user_uuid_by_ldap_attribute(self, user_email):
        try:
            user = next(iter(self._user_service.list_users(email_address=user_email)))
        except StopIteration:
            logger.warning(
                '%s does not have an email associated with an auth user', user_email
            )
            return
        return user['uuid']

    def _build_dn_with_config(self, login):
        login_esc = escape_dn_chars(login)
        return '{}={},{}'.format(
            self.user_login_attribute, login_esc, self.user_base_dn
        )

    def _get_user_ldap_email(self, wazo_ldap, user_dn):
        _, obj = wazo_ldap.perform_search(
            user_dn, ldap.SCOPE_BASE, attrlist=[self.user_email_attribute]
        )
        email = obj.get(self.user_email_attribute, None)
        email = email[0] if isinstance(email, list) else email
        if not email:
            logger.debug('LDAP : No email found for the user DN: %s', user_dn)
            return
        return email.decode('utf-8')

    def _perform_search_dn(self, wazo_ldap, username):
        username_esc = escape_filter_chars(username)
        filterstr = '{}={}'.format(self.user_login_attribute, username_esc)
        dn, _ = wazo_ldap.perform_search(
            self.user_base_dn, ldap.SCOPE_SUBTREE, filterstr=filterstr, attrlist=['']
        )
        if not dn:
            logger.debug(
                'LDAP : No user DN for user_base dn: %s and filterstr: %s',
                self.user_base_dn,
                filterstr,
            )
        return dn


class _WazoLDAP:
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
