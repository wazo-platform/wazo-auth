#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

from setuptools import find_packages
from setuptools import setup

on_travis = os.getenv('TRAVIS_RUN', '0') == '1'
data_files = [] if on_travis else [('/etc/xivo-auth', ['etc/xivo-auth/config.yml'])]


setup(
    name='xivo_auth',
    version='0.1',

    description='XiVO auth',

    author='Avencall',
    author_email='dev@avencall.com',

    url='https://github.com/xivo-pbx/xivo-auth',

    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,

    package_data={
        'xivo_auth.swagger': ['*.json'],
    },

    scripts=['bin/xivo-auth'],
    data_files=data_files,

    entry_points={
        'xivo_auth.backends': [
            'xivo_user = xivo_auth.plugins.backends:XiVOUser',
            'mock = xivo_auth.plugins.backends:BackendMock',
            'broken_init = xivo_auth.plugins.backends:BrokenInitBackend',
            'broken_verify_password = xivo_auth.plugins.backends:BrokenVerifyPasswordBackend',
        ],
    }
)
