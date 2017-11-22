#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2016-2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+


from setuptools import find_packages
from setuptools import setup

setup(
    name='wazo_auth',
    version='0.1',

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
            'wazo-auth=wazo_auth.main:main',
        ],
        'wazo_auth.http': [
            'api = wazo_auth.plugins.http.api.plugin:Plugin',
            'groups = wazo_auth.plugins.http.groups.plugin:Plugin',
            'policies = wazo_auth.plugins.http.policies.plugin:Plugin',
            'tenants = wazo_auth.plugins.http.tenants.plugin:Plugin',
            'tenant_user = wazo_auth.plugins.http.tenant_user.plugin:Plugin',
            'users = wazo_auth.plugins.http.users.plugin:Plugin',
            'user_group = wazo_auth.plugins.http.user_group.plugin:Plugin',
            'user_policy = wazo_auth.plugins.http.user_policy.plugin:Plugin',
        ],
        'wazo_auth.backends': [
            'wazo_user = wazo_auth.plugins.backends:WazoUser',
            'xivo_admin = wazo_auth.plugins.backends:XiVOAdmin',
            'xivo_service = wazo_auth.plugins.backends:XiVOService',
            'xivo_user = wazo_auth.plugins.backends:XiVOUser',
            'ldap_user = wazo_auth.plugins.backends:LDAPUser',
            'mock = wazo_auth.plugins.backends:BackendMock',
            'mock_with_uuid = wazo_auth.plugins.backends:BackendMockWithUUID',
            'broken_init = wazo_auth.plugins.backends:BrokenInitBackend',
            'broken_verify_password = wazo_auth.plugins.backends:BrokenVerifyPasswordBackend',
        ],
    }
)
