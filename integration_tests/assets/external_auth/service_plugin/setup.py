#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+


from setuptools import find_packages
from setuptools import setup

setup(
    name='foo and bar service auth plugin',
    version='0.1',

    packages=find_packages(),
    entry_points={
        'wazo_auth.external_auth': [
            'foo = src.plugin:FooPlugin',
            'bar = src.plugin:BarPlugin',
        ],
    }
)
