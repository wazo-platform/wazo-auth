#!/usr/bin/env python
# Copyright 2025 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later


from setuptools import find_packages, setup

setup(
    name='testing email driver plugin',
    version='0.1',
    packages=find_packages(),
    entry_points={
        'wazo_auth.email_notification': [
            'logger = email_notification_logger.plugin:Plugin',
        ]
    },
)
