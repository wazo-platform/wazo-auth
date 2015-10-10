from xivo_auth import BaseAuthenticationBackend
from ldap_backend import XivoLDAP
from xivo_dao import user_dao

class LDAPUser(BaseAuthenticationBackend):
    def __init__(self, config):
        self.config = config['ldap']
        self.domain = self.config['domain']
        self.ldap = XivoLDAP(self.config)

    def get_consul_acls(self, username, args):
        identifier, _ = self.get_ids(username, args)
        rules = [{'rule': 'xivo/private/{identifier}'.format(identifier=identifier),
                  'policy': 'write'}]
        return rules

    def get_acls(self, login, args):
        return ['acl:dird']

    def get_ids(self, username, args):
        user_uuid = user_dao.get_uuid_by_email(self._set_username_with_domain(username))
        return user_uuid, user_uuid

    def verify_password(self, username, password):
        return self.ldap.perform_bind(self._set_username_without_domain(username), password)

    def _get_username(self, username):
        if '@' in username:
            username, domain = username.split('@', username)
        return username

    def _set_username_without_domain(self, username):
        return "%s=%s,%s" %(self.config['prefix'], self._get_username(username), self.config['basedn'])

    def _set_username_with_domain(self, username):
        if not '@' in username:
            username = username + "@" + self.domain
        return username
