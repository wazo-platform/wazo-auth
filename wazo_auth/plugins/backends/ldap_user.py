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
        login_to_use = args.get('user_email') or login
        user_uuid = self._user_service.get_user_uuid_by_login(login_to_use)
        group_acl = self._group_service.get_acl(user_uuid)
        user_acl = self._user_service.get_acl(user_uuid)
        return backend_acl + group_acl + user_acl

    def get_metadata(self, login, args):
        metadata = super().get_metadata(login, args)
        login_to_use = args.get('user_email') or login
        user_uuid = self._user_service.get_user_uuid_by_login(login_to_use)
        metadata['auth_id'] = user_uuid
        purpose = self._user_service.list_users(uuid=user_uuid)[0]['purpose']
        for plugin in self._purposes.get(purpose).metadata_plugins:
            metadata.update(plugin.get_token_metadata(login_to_use, args))
        return metadata

    def verify_password(self, username, password, args):
        if 'domain_name' in args:
            top_tenant_uuid = self._tenant_service.find_top_tenant()
            tenants = self._tenant_service.list_(
                top_tenant_uuid, domain_name=args['domain_name']
            )
            if not tenants:
                logger.warning(
                    'Failed login using non-existing domain_name: %s',
                    args['domain_name'],
                )
                return False
            tenant_uuid = tenants[0]['uuid']
        elif 'tenant_id' in args:
            # tenant_id was deprecated in wazo 22.07
            tenant_uuid = self._get_tenant(args['tenant_id'])['uuid']
            logger.warning(
                'LDAP login using the "tenant_id" is deprecated. Use "domain_name" instead'
            )

        config = self._get_ldap_config(tenant_uuid)
        if not config:
            logger.warning(
                'Could not login: no LDAP config for tenant "%s"', tenant_uuid
            )
            return False

        bind_dn = config.get('bind_dn')
        bind_password = config.get('bind_password')
        user_login_attribute = config.get('user_login_attribute')
        user_email_attribute = config.get('user_email_attribute')
        user_base_dn = config.get('user_base_dn')
        search_filters = config.get('search_filters')

        wazo_ldap = _WazoLDAP(config)
        user_email = None
        try:
            wazo_ldap.connect()
            if bind_dn and bind_password:
                if wazo_ldap.perform_bind(bind_dn, bind_password):
                    user_dn, user_email = self._perform_search_attributes(
                        wazo_ldap,
                        username,
                        user_login_attribute,
                        user_email_attribute,
                        user_base_dn,
                        search_filters=search_filters,
                    )
                else:
                    logger.warning(
                        'Could not login: service-level bind failed for "%s" on tenant "%s"',
                        bind_dn,
                        tenant_uuid,
                    )
                    return False
            else:
                user_dn = self._build_dn_with_config(
                    username, user_login_attribute, user_base_dn
                )

            if not user_dn or not wazo_ldap.perform_bind(user_dn, password):
                logger.debug(
                    'Could not login: invalid credentials for user "%s" on tenant "%s"',
                    user_dn,
                    tenant_uuid,
                )
                return False

            if not user_email:
                user_email = self._get_user_ldap_email(
                    wazo_ldap, user_dn, user_email_attribute
                )
            if not user_email:
                logger.debug(
                    'Could not login: the LDAP user "%s" does not have an email address',
                    user_dn,
                )
                return False

        except ldap.SERVER_DOWN:
            logger.warning('LDAP : SERVER not responding on "%s"', wazo_ldap.uri)
            return False
        except ldap.LDAPError as exc:
            logger.exception('ldap.LDAPError (%r, %r)', config, exc)
            return False

        pbx_user = self._get_user_by_ldap_attribute(user_email, tenant_uuid)
        if not pbx_user:
            logger.debug(
                'Could not log in: user "%s" could not be found in tenant "%s"',
                user_email,
                tenant_uuid,
            )
            return False

        args['pbx_user_uuid'] = pbx_user['uuid']
        args['user_email'] = user_email
        args['real_login'] = user_email

        return True

    def _get_ldap_config(self, tenant_uuid):
        return self._ldap_service.get(tenant_uuid)

    def _get_tenant(self, tenant_id):
        return self._tenant_service.get_by_uuid_or_slug(None, tenant_id)

    def _get_user_by_ldap_attribute(self, user_email, tenant_uuid):
        for user in self._user_service.list_users(tenant_uuid=tenant_uuid):
            if 'emails' in user.keys():
                if user['emails']:
                    wazo_auth_user_email = user['emails'][0]['address']
                    if wazo_auth_user_email.lower() == user_email.lower():
                        return user
        logger.warning(
            '%s does not have an email associated with an auth user', user_email
        )

    def _build_dn_with_config(self, login, user_login_attribute, user_base_dn):
        login_esc = escape_dn_chars(login)
        return f'{user_login_attribute}={login_esc},{user_base_dn}'

    def _get_user_ldap_email(self, wazo_ldap, user_dn, user_email_attribute):
        _, obj = wazo_ldap.perform_search(
            user_dn, ldap.SCOPE_BASE, attrlist=[user_email_attribute]
        )
        email = self._extract_email_attribute(obj, user_email_attribute)
        if not email:
            logger.debug('LDAP : No email found for the user DN: %s', user_dn)
            return
        return email

    def _extract_email_attribute(self, ldap_obj, user_email_attribute):
        email = ldap_obj.get(user_email_attribute, None)
        email = email[0] if isinstance(email, list) else email
        return email.decode('utf-8') if email else None

    def _perform_search_attributes(
        self,
        wazo_ldap,
        username,
        user_login_attribute,
        user_email_attribute,
        user_base_dn,
        search_filters=None,
    ):
        if not search_filters:
            search_filters = '{user_login_attribute}={username}'

        filterstr = search_filters.format(
            username=escape_filter_chars(username),
            user_login_attribute=escape_filter_chars(user_login_attribute),
            user_email_attribute=escape_filter_chars(user_email_attribute),
        )

        dn, obj = wazo_ldap.perform_search(
            user_base_dn,
            ldap.SCOPE_SUBTREE,
            filterstr=filterstr,
            attrlist=[user_email_attribute],
        )
        if not dn:
            logger.debug(
                'LDAP : No user DN for user_base dn: %s and filterstr: %s',
                user_base_dn,
                filterstr,
            )
            return None, None
        return dn, self._extract_email_attribute(obj, user_email_attribute)


class _WazoLDAP:
    def __init__(self, config):
        self.config = config
        self.uri = self._build_uri(
            config['protocol_security'], config['port'], config['host']
        )

    def connect(self):
        self.ldapobj = self._create_ldap_obj(self.config)

    def _build_uri(self, protocol_security, port, host):
        scheme = 'ldaps' if protocol_security == 'ldaps' else 'ldap'
        return f'{scheme}://{host}:{port}'

    def _create_ldap_obj(self, config):
        ldapobj = ldap.initialize(self.uri)
        ldapobj.set_option(ldap.OPT_REFERRALS, 0)
        ldapobj.set_option(ldap.OPT_NETWORK_TIMEOUT, 2)
        ldapobj.set_option(ldap.OPT_TIMEOUT, 2)

        version_map = {
            2: ldap.VERSION2,
            3: ldap.VERSION3,
        }
        ldapobj.set_option(
            ldap.OPT_PROTOCOL_VERSION, version_map.get(config['protocol_version'], 3)
        )

        if config['protocol_security'] == 'tls':
            ldapobj.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
            ldapobj.start_tls_s()
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
