#!/usr/bin/env python
# Copyright 2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


from setuptools import find_packages, setup

setup(
    name='testing internal token metadata auth plugin',
    version='0.1',
    packages=find_packages(),
    entry_points={
        'wazo_auth.metadata': [
            'internal_token = metadata_internal_token.plugin:Plugin',
        ]
    },
)
