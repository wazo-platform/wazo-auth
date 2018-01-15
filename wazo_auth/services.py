# -*- coding: utf-8 -*-
# Copyright 2017-2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import binascii
import hashlib
import logging
import os
import time

import smtplib
from collections import namedtuple
from email import utils as email_utils
from email.mime.text import MIMEText

from jinja2 import BaseLoader, Environment, TemplateNotFound
from os import path
from xivo_bus.resources.auth import events
from xivo.consul_helpers import address_from_config
from . import exceptions

logger = logging.getLogger(__name__)


EmailDestination = namedtuple('EmailDestination', ['name', 'address'])


class _Service(object):

    def __init__(self, dao):
        self._dao = dao


class EmailService(_Service):

    def __init__(self, dao, config):
        super(EmailService, self).__init__(dao)
        self._email_formatter = EmailFormatter(config)
        self._smtp_host = config['smtp']['hostname']
        self._smtp_port = config['smtp']['port']
        self._token_expiration = config['email_confirmation_expiration']
        self._from = EmailDestination(
            config['email_confirmation_from_name'],
            config['email_confirmation_from_address'],
        )

    def confirm(self, email_uuid):
        self._dao.email.confirm(email_uuid)

    def send_confirmation_email(self, username, email_uuid, email_address):
        template_context = dict(
            token=self._new_email_confirmation_token(email_uuid),
            username=username,
            email_uuid=email_uuid,
            email_address=email_address,
        )

        body = self._email_formatter.format_confirmation_email(template_context)
        subject = self._email_formatter.format_confirmation_subject(template_context)
        to = EmailDestination(username, email_address)
        self._send_msg(to, self._from, subject, body)

    def _send_msg(self, to, from_, subject, body):
        msg = MIMEText(body)
        msg['To'] = email_utils.formataddr(to)
        msg['From'] = email_utils.formataddr(from_)
        msg['Subject'] = subject

        server = smtplib.SMTP(self._smtp_host, self._smtp_port)
        try:
            server.sendmail(from_.address, [to.address], msg.as_string())
        finally:
            server.close()

    def _new_email_confirmation_token(self, email_uuid):
        t = time.time()
        token_payload = dict(
            auth_id='wazo-auth',
            xivo_user_uuid=None,
            xivo_uuid=None,
            expire_t=t+self._token_expiration,
            issued_t=t,
            acls=['auth.emails.{}.confirm.edit'.format(email_uuid)],
        )
        return self._dao.token.create(token_payload)


class ExternalAuthService(_Service):

    def __init__(self, dao, bus_publisher=None, enabled_external_auth=None):
        super(ExternalAuthService, self).__init__(dao)
        self._bus_publisher = bus_publisher
        self._safe_models = {}
        self._enabled_external_auth = enabled_external_auth or []
        self._enabled_external_auth_populated = False

    def _populate_enabled_external_auth(self):
        if self._enabled_external_auth_populated:
            return
        self._dao.external_auth.enable_all(self._enabled_external_auth)
        self._enabled_external_auth_populated = True

    def count(self, user_uuid, **kwargs):
        self._populate_enabled_external_auth()
        return self._dao.external_auth.count(user_uuid, **kwargs)

    def create(self, user_uuid, auth_type, data):
        result = self._dao.external_auth.create(user_uuid, auth_type, data)
        event = events.UserExternalAuthAdded(user_uuid, auth_type)
        self._bus_publisher.publish(event)
        return result

    def delete(self, user_uuid, auth_type):
        self._dao.external_auth.delete(user_uuid, auth_type)
        event = events.UserExternalAuthDeleted(user_uuid, auth_type)
        self._bus_publisher.publish(event)

    def get(self, user_uuid, auth_type):
        return self._dao.external_auth.get(user_uuid, auth_type)

    def list_(self, user_uuid, **kwargs):
        self._populate_enabled_external_auth()
        raw_external_auth_info = self._dao.external_auth.list_(user_uuid, **kwargs)
        result = []
        for external_auth in raw_external_auth_info:
            auth_type = external_auth['type']
            enabled = external_auth['enabled']
            Model = self._safe_models.get(auth_type)
            filtered_data = {}
            if Model:
                data = external_auth.get('data')
                filtered_data, errors = Model().load(data)
                if errors:
                    logger.info('Failed to parse %s data for user %s: %s', auth_type, user_uuid, errors)
            result.append({'type': auth_type, 'data': filtered_data, 'enabled': enabled})
        return result

    def register_safe_auth_model(self, auth_type, model_class):
        self._safe_models[auth_type] = model_class

    def update(self, user_uuid, auth_type, data):
        return self._dao.external_auth.update(user_uuid, auth_type, data)


class GroupService(_Service):

    def add_policy(self, group_uuid, policy_uuid):
        return self._dao.group.add_policy(group_uuid, policy_uuid)

    def add_user(self, group_uuid, user_uuid):
        return self._dao.group.add_user(group_uuid, user_uuid)

    def count(self, **kwargs):
        return self._dao.group.count(**kwargs)

    def count_policies(self, group_uuid, **kwargs):
        return self._dao.group.count_policies(group_uuid, **kwargs)

    def count_users(self, group_uuid, **kwargs):
        return self._dao.group.count_users(group_uuid, **kwargs)

    def create(self, **kwargs):
        uuid = self._dao.group.create(**kwargs)
        return dict(uuid=uuid, **kwargs)

    def delete(self, group_uuid):
        return self._dao.group.delete(group_uuid)

    def get(self, group_uuid):
        matching_groups = self._dao.group.list_(uuid=group_uuid, limit=1)
        for group in matching_groups:
            return group
        raise exceptions.UnknownGroupException(group_uuid)

    def get_acl_templates(self, username):
        users = self._dao.user.list_(username=username, limit=1)
        acl_templates = []
        for user in users:
            groups = self._dao.group.list_(user_uuid=user['uuid'])
            for group in groups:
                policies = self.list_policies(group['uuid'])
                for policy in policies:
                    acl_templates.extend(policy['acl_templates'])
        return acl_templates

    def list_(self, **kwargs):
        return self._dao.group.list_(**kwargs)

    def list_policies(self, group_uuid, **kwargs):
        return self._dao.policy.get(group_uuid=group_uuid, **kwargs)

    def list_users(self, group_uuid, **kwargs):
        return self._dao.user.list_(group_uuid=group_uuid, **kwargs)

    def remove_policy(self, group_uuid, policy_uuid):
        nb_deleted = self._dao.group.remove_policy(group_uuid, policy_uuid)
        if nb_deleted:
            return

        if not self._dao.group.exists(group_uuid):
            raise exceptions.UnknownGroupException(group_uuid)

        if not self._dao.policy.exists(policy_uuid):
            raise exceptions.UnknownPolicyException(policy_uuid)

    def remove_user(self, group_uuid, user_uuid):
        nb_deleted = self._dao.group.remove_user(group_uuid, user_uuid)
        if nb_deleted:
            return

        if not self._dao.group.exists(group_uuid):
            raise exceptions.UnknownGroupException(group_uuid)

        if not self._dao.user.exists(user_uuid):
            raise exceptions.UnknownUserException(user_uuid)

    def update(self, group_uuid, **kwargs):
        return self._dao.group.update(group_uuid, **kwargs)


class PolicyService(_Service):

    def add_acl_template(self, policy_uuid, acl_template):
        return self._dao.policy.associate_policy_template(policy_uuid, acl_template)

    def create(self, **kwargs):
        return self._dao.policy.create(**kwargs)

    def count(self, **kwargs):
        return self._dao.policy.count(**kwargs)

    def delete(self, policy_uuid):
        return self._dao.policy.delete(policy_uuid)

    def delete_acl_template(self, policy_uuid, acl_template):
        nb_deleted = self._dao.policy.dissociate_policy_template(policy_uuid, acl_template)
        if nb_deleted:
            return

        if not self._dao.policy.exists(policy_uuid):
            raise exceptions.UnknownPolicyException(policy_uuid)

    def get(self, policy_uuid):
        matching_policies = self._dao.policy.get(uuid=policy_uuid)
        for policy in matching_policies:
            return policy
        raise exceptions.UnknownPolicyException(policy_uuid)

    def list(self, **kwargs):
        return self._dao.policy.get(**kwargs)

    def update(self, policy_uuid, **body):
        self._dao.policy.update(policy_uuid, **body)
        return dict(uuid=policy_uuid, **body)


class TenantService(_Service):

    def add_user(self, tenant_uuid, user_uuid):
        return self._dao.tenant.add_user(tenant_uuid, user_uuid)

    def count_users(self, tenant_uuid, **kwargs):
        return self._dao.tenant.count_users(tenant_uuid, **kwargs)

    def count(self, **kwargs):
        return self._dao.tenant.count(**kwargs)

    def delete(self, uuid):
        return self._dao.tenant.delete(uuid)

    def get(self, uuid):
        tenants = self._dao.tenant.list_(uuid=uuid, limit=1)
        for tenant in tenants:
            return tenant
        raise exceptions.UnknownTenantException(uuid)

    def list_(self, **kwargs):
        return self._dao.tenant.list_(**kwargs)

    def list_users(self, tenant_uuid, **kwargs):
        return self._dao.user.list_(tenant_uuid=tenant_uuid, **kwargs)

    def new(self, **kwargs):
        address_id = self._dao.address.new(**kwargs['address'])
        uuid = self._dao.tenant.create(address_id=address_id, **kwargs)
        return self.get(uuid)

    def remove_user(self, tenant_uuid, user_uuid):
        nb_deleted = self._dao.tenant.remove_user(tenant_uuid, user_uuid)
        if nb_deleted:
            return

        if not self._dao.tenant.exists(tenant_uuid):
            raise exceptions.UnknownTenantException(tenant_uuid)

        if not self._dao.user.exists(user_uuid):
            raise exceptions.UnknownUserException(user_uuid)

    def update(self, tenant_uuid, **kwargs):
        address_id = self._dao.tenant.get_address_id(tenant_uuid)
        if not address_id:
            address_id = self._dao.address.new(**kwargs['address'])
        else:
            address_id, self._dao.address.update(address_id, **kwargs['address'])

        self._dao.tenant.update(tenant_uuid, address_id=address_id, **kwargs)

        return self.get(tenant_uuid)


class UserService(_Service):

    def __init__(self, dao, encrypter=None):
        super(UserService, self).__init__(dao)
        self._encrypter = encrypter or PasswordEncrypter()

    def add_policy(self, user_uuid, policy_uuid):
        self._dao.user.add_policy(user_uuid, policy_uuid)

    def change_password(self, user_uuid, old_password, new_password):
        user = self.get_user(user_uuid)
        if not self.verify_password(user['username'], old_password):
            raise exceptions.AuthenticationFailedException()

        salt, hash_ = self._encrypter.encrypt_password(new_password)
        self._dao.user.change_password(user_uuid, salt, hash_)

    def delete_password(self, **kwargs):
        search_params = {k: v for k, v in kwargs.iteritems() if v}
        identifier = search_params.values()[0]

        logger.debug('removing password for user %s', identifier)
        users = self._dao.user.list_(limit=1, **search_params)
        if not users:
            raise exceptions.UnknownUserException(identifier, details=kwargs)

        for user in users:
            self._dao.user.change_password(user['uuid'], salt=None, hash_=None)
            return user

    def count_groups(self, user_uuid, **kwargs):
        return self._dao.user.count_groups(user_uuid, **kwargs)

    def count_policies(self, user_uuid, **kwargs):
        return self._dao.user.count_policies(user_uuid, **kwargs)

    def count_tenants(self, user_uuid, **kwargs):
        return self._dao.user.count_tenants(user_uuid, **kwargs)

    def count_users(self, **kwargs):
        return self._dao.user.count(**kwargs)

    def delete_user(self, user_uuid):
        self._dao.user.delete(user_uuid)

    def get_acl_templates(self, username):
        users = self._dao.user.list_(username=username, limit=1)
        acl_templates = []
        for user in users:
            policies = self.list_policies(user['uuid'])
            for policy in policies:
                acl_templates.extend(policy['acl_templates'])
        return acl_templates

    def get_user(self, user_uuid):
        users = self._dao.user.list_(uuid=user_uuid)
        for user in users:
            return user
        raise exceptions.UnknownUserException(user_uuid)

    def list_groups(self, user_uuid, **kwargs):
        return self._dao.group.list_(user_uuid=user_uuid, **kwargs)

    def list_policies(self, user_uuid, **kwargs):
        return self._dao.policy.get(user_uuid=user_uuid, **kwargs)

    def list_tenants(self, user_uuid, **kwargs):
        return self._dao.tenant.list_(user_uuid=user_uuid, **kwargs)

    def list_users(self, **kwargs):
        return self._dao.user.list_(**kwargs)

    def new_user(self, **kwargs):
        password = kwargs.pop('password', None)
        if password:
            kwargs['salt'], kwargs['hash_'] = self._encrypter.encrypt_password(password)

        logger.info('creating a new user with params: %s', kwargs)  # log after poping the password
        return self._dao.user.create(**kwargs)

    def remove_policy(self, user_uuid, policy_uuid):
        nb_deleted = self._dao.user.remove_policy(user_uuid, policy_uuid)
        if nb_deleted:
            return

        if not self._dao.user.exists(user_uuid):
            raise exceptions.UnknownUserException(user_uuid)

        if not self._dao.policy.exists(policy_uuid):
            raise exceptions.UnknownPolicyException(policy_uuid)

    def update(self, user_uuid, **kwargs):
        self._dao.user.update(user_uuid, **kwargs)
        return self.get_user(user_uuid)

    def verify_password(self, username, password):
        try:
            hash_, salt = self._dao.user.get_credentials(username)
        except exceptions.UnknownUsernameException:
            return False

        if not hash_ or not salt:
            return False

        return hash_ == self._encrypter.compute_password_hash(password, salt)


class TemplateLoader(BaseLoader):

    _templates = dict(
        email_confirmation='email_confirmation_template',
        email_confirmation_subject='email_confirmation_subject_template',
        reset_password='reset_password_email_template',
        reset_password_subject='reset_password_email_subject_template',
    )

    def __init__(self, config):
        self._config = config

    def get_source(self, environment, template):
        config_key = self._templates.get(template)
        if not config_key:
            raise TemplateNotFound(template)

        template_path = self._config[config_key]
        if not path.exists(template_path):
            raise TemplateNotFound(template)

        mtime = path.getmtime(template_path)
        with file(template_path) as f:
            source = f.read().decode('utf-8')

        return source, template_path, lambda: mtime == path.getmtime(template_path)


class EmailFormatter(object):

    def __init__(self, config):
        self.environment = Environment(
            loader=TemplateLoader(config),
        )
        self.environment.globals['port'] = config['service_discovery']['advertise_port']
        self.environment.globals['hostname'] = address_from_config(config['service_discovery'])

    def format_confirmation_email(self, context):
        template = self.environment.get_template('email_confirmation')
        return template.render(**context)

    def format_confirmation_subject(self, context):
        template = self.environment.get_template('email_confirmation_subject')
        return template.render(**context)

    def format_password_reset_email(self, context):
        template = self.environment.get_template('reset_password')
        return template.render(**context)

    def format_password_reset_subject(self, context):
        template = self.environment.get_template('reset_password_subject')
        return template.render(**context)


class PasswordEncrypter(object):

    _salt_len = 64
    _hash_algo = 'sha512'
    _iterations = 250000

    def encrypt_password(self, password):
        salt = os.urandom(self._salt_len)
        hash_ = self.compute_password_hash(password, salt)
        return salt, hash_

    def compute_password_hash(self, password, salt):
        password_bytes = password.encode('utf-8')
        dk = hashlib.pbkdf2_hmac(self._hash_algo, password_bytes, salt, self._iterations)
        return binascii.hexlify(dk)
