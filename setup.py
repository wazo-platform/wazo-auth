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
    name='xivo_auth',
    version='0.1',

    description='XiVO auth',

    author='Wazo Authors',
    author_email='dev@wazo.community',

    url='http://wazo.community',

    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,

    package_data={
        'xivo_auth.swagger': ['*.yml'],
    },

    scripts=[
        'bin/wazo-auth-init-db',
    ],

    entry_points={
        'console_scripts': [
            'xivo-auth=xivo_auth.bin.daemon:main',
        ],
        'xivo_auth.backends': [
            'xivo_admin = xivo_auth.plugins.backends:XiVOAdmin',
            'xivo_service = xivo_auth.plugins.backends:XiVOService',
            'xivo_user = xivo_auth.plugins.backends:XiVOUser',
            'ldap_user = xivo_auth.plugins.backends:LDAPUser',
            'mock = xivo_auth.plugins.backends:BackendMock',
            'mock_with_uuid = xivo_auth.plugins.backends:BackendMockWithUUID',
            'broken_init = xivo_auth.plugins.backends:BrokenInitBackend',
            'broken_verify_password = xivo_auth.plugins.backends:BrokenVerifyPasswordBackend',
        ],
    }
)
