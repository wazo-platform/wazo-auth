# Copyright 2016-2019 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from setuptools import find_packages
from setuptools import setup

setup(
    name='wazo_auth',
    version='1.0',

    description='Wazo auth',

    author='Wazo Authors',
    author_email='dev@wazo.community',

    url='http://wazo.community',

    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    package_data={
        'wazo_auth.plugins.http': ['*/api.yml'],
    },
    scripts=[
        'bin/wazo-auth-init-db',
    ],

    entry_points={
        'console_scripts': [
            'wazo-auth = wazo_auth.main:main',
            'wazo-auth-bootstrap = wazo_auth.bootstrap:main',
        ],
        'wazo_auth.backends': [
            'wazo_user = wazo_auth.plugins.backends.wazo_user:WazoUser',
            'ldap_user = wazo_auth.plugins.backends.ldap_user:LDAPUser',
            'broken_init = wazo_auth.plugins.backends.broken:BrokenInitBackend',
            'broken_verify_password = wazo_auth.plugins.backends.broken:BrokenVerifyPasswordBackend',
        ],
        'wazo_auth.http': [
            'api = wazo_auth.plugins.http.api.plugin:Plugin',
            'backends = wazo_auth.plugins.http.backends.plugin:Plugin',
            'email_confirm = wazo_auth.plugins.http.email_confirm.plugin:Plugin',
            'external = wazo_auth.plugins.http.external.plugin:Plugin',
            'groups = wazo_auth.plugins.http.groups.plugin:Plugin',
            'group_policy = wazo_auth.plugins.http.group_policy.plugin:Plugin',
            'init = wazo_auth.plugins.http.init.plugin:Plugin',
            'password_reset = wazo_auth.plugins.http.password_reset.plugin:Plugin',
            'policies = wazo_auth.plugins.http.policies.plugin:Plugin',
            'sessions = wazo_auth.plugins.http.sessions.plugin:Plugin',
            'tenants = wazo_auth.plugins.http.tenants.plugin:Plugin',
            'tenant_user = wazo_auth.plugins.http.tenant_user.plugin:Plugin',
            'tenant_policy = wazo_auth.plugins.http.tenant_policy.plugin:Plugin',
            'tokens = wazo_auth.plugins.http.tokens.plugin:Plugin',
            'users = wazo_auth.plugins.http.users.plugin:Plugin',
            'user_email = wazo_auth.plugins.http.user_email.plugin:Plugin',
            'user_registration = wazo_auth.plugins.http.user_registration.plugin:Plugin',
            'user_group = wazo_auth.plugins.http.user_group.plugin:Plugin',
            'user_policy = wazo_auth.plugins.http.user_policy.plugin:Plugin',
            'user_session = wazo_auth.plugins.http.user_session.plugin:Plugin',
        ],
        'wazo_auth.external_auth': [
            'mobile = wazo_auth.plugins.external_auth.mobile.plugin:Plugin',
        ],
        'wazo_auth.metadata': [
            'default_user = wazo_auth.plugins.metadata.default_user:DefaultUser',
            'default_internal = wazo_auth.plugins.metadata.default_internal:DefaultInternal',
            'default_external_api = wazo_auth.plugins.metadata.default_external_api:DefaultExternalAPI',
        ],
    }
)
