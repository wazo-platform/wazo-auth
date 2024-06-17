#!/usr/bin/env python
# Copyright 2017-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


from setuptools import find_packages, setup

setup(
    name='foo and bar service auth plugin',
    version='0.1',
    packages=find_packages(),
    entry_points={
        'wazo_auth.external_auth': [
            'foo = external_auth_service_plugin.plugin:FooPlugin',
            'bar = external_auth_service_plugin.plugin:BarPlugin',
        ]
    },
)
