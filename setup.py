#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2016-2017 The Wazo Authors  (see the AUTHORS file)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>


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
        'wazo_auth.swagger': ['*.yml'],
    },

    scripts=[
        'bin/wazo-auth-init-db',
    ],

    entry_points={
        'console_scripts': [
            'wazo-auth=wazo_auth.main:main',
        ],
        'wazo_auth.http': [
            'users = wazo_auth.plugins.http.users:Plugin',
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
