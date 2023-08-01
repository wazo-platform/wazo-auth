# Copyright 2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from cas import CASClient

from wazo_auth import BaseAuthenticationBackend

logger = logging.getLogger(__name__)


def caseless_equal(str1: str, str2: str):
    return str1.casefold() == str2.casefold()


class CASUser(BaseAuthenticationBackend):
    def load(self, dependencies):
        super().load(dependencies)
        self._user_service = dependencies['user_service']
        self._group_service = dependencies['group_service']
        self._purposes = dependencies['purposes']
        self._cas_service = dependencies['cas_service']
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
        top_tenant_uuid = self._tenant_service.find_top_tenant()
        tenants = self._tenant_service.list_(
            top_tenant_uuid, domain_name=args['domain_name']
        )
        if not tenants:
            logger.warning(
                'Failed login using non-existing domain_name: "%s"',
                args['domain_name'],
            )
            return False
        tenant_uuid = tenants[0]['uuid']

        config = self._get_cas_config(tenant_uuid)
        if not config:
            logger.warning(
                'Could not login: no CAS config for tenant "%s"', tenant_uuid
            )
            return False

        ticket = args.get('ticket')
        if not ticket:
            logger.warning('Failed login: empty or no CAS ticket')
            return False

        # Check ticket against the CAS server
        # First get the CAS configuration and build a client
        cas_client = CASClient(
            version=3,
            server_url=config['server_url'],
            service_url=config['service_url'],
        )

        user, attrs, _ = cas_client.verify_ticket(ticket)
        if not user:
            return False

        user_email = attrs.get(config['user_email_attribute'])
        if not user_email:
            logger.warning(
                'Failed login: the user does not have an email address in its CAS attributes'
            )
            return False

        pbx_user = self._get_user_by_email_attribute(user_email, tenant_uuid)
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

    def _get_cas_config(self, tenant_uuid):
        return self._cas_service.get(tenant_uuid)

    def _get_tenant(self, tenant_id):
        return self._tenant_service.get_by_uuid_or_slug(None, tenant_id)

    def _get_user_by_email_attribute(self, user_email, tenant_uuid):
        for user in self._user_service.list_users(tenant_uuid=tenant_uuid):
            user_emails = user.get('emails')
            if user_emails:
                for email in user_emails:
                    if caseless_equal(email.get('address', ''), user_email):
                        return user
            username = user.get('username')
            if username:
                if caseless_equal(username, user_email):
                    return user
        logger.warning(
            '"%s" does not have an email associated with an auth user', user_email
        )
