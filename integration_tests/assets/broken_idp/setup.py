# Copyright 2016-2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from setuptools import find_packages, setup

setup(
    name='wazo_auth_broken_idp',
    version='1.0',
    description='A broken wazo_auth.idp plugin implementation for testing',
    packages=find_packages(),
    entry_points={
        'wazo_auth.idp': [
            'broken_load = broken_idp.plugin:BrokenLoadIDP',
            'broken_can_authenticate = broken_idp.plugin:BrokenCanAuthenticateIDP',
            'broken_verify_auth = broken_idp.plugin:BrokenVerifyAuthIDP',
            'broken_verify_auth_replacement = broken_idp.plugin:BrokenVerifyAuthReplacementIDP',
        ],
    },
)
