# Copyright 2021 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest
from .helpers import base as asset


def pytest_collection_modifyitems(session, config, items):
    # item == test method
    # item.parent == test class
    # item.parent.own_markers == pytest markers of the test class
    # item.parent.own_markers[0].args[0] == name of the asset
    # It also remove the run-order pytest feature (--ff, --nf)
    items.sort(key=lambda item: item.parent.own_markers[0].args[0])


@pytest.fixture(scope='session')
def base():
    asset.APIAssetLaunchingTestCase.setUpClass()
    try:
        yield
    finally:
        asset.APIAssetLaunchingTestCase.tearDownClass()


@pytest.fixture(scope='session')
def database():
    asset.DBAssetLaunchingTestCase.setUpClass()
    try:
        yield
    finally:
        asset.DBAssetLaunchingTestCase.tearDownClass()


@pytest.fixture(scope='session')
def external_auth():
    asset.ExternalAuthAssetLaunchingTestCase.setUpClass()
    try:
        yield
    finally:
        asset.ExternalAuthAssetLaunchingTestCase.tearDownClass()


# Legacy LDAP
@pytest.fixture(scope='session')
def ldap():
    asset.LDAPAssetLaunchingTestCase.setUpClass()
    try:
        yield
    finally:
        asset.LDAPAssetLaunchingTestCase.tearDownClass()


# Legacy LDAP
@pytest.fixture(scope='session')
def ldap_anonymous():
    asset.LDAPAnonymousAssetLaunchingTestCase.setUpClass()
    try:
        yield
    finally:
        asset.LDAPAnonymousAssetLaunchingTestCase.tearDownClass()


# Legacy LDAP
@pytest.fixture(scope='session')
def ldap_service_user():
    asset.LDAPServiceUserAssetLaunchingTestCase.setUpClass()
    try:
        yield
    finally:
        asset.LDAPServiceUserAssetLaunchingTestCase.tearDownClass()
