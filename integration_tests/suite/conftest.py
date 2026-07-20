# Copyright 2021-2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest
from wazo_test_helpers.pytest_asset import (
    asset_fixture,
    enable_mark_logs_fixture,
    register,
)

from .helpers import base as asset


def pytest_configure(config):
    register(config)


base = asset_fixture(asset.APIAssetLaunchingTestCase)
saml = asset_fixture(asset.SAMLAssetLaunchingTestCase)
database = asset_fixture(asset.DBAssetLaunchingTestCase)
external_auth = asset_fixture(asset.ExternalAuthAssetLaunchingTestCase)
metadata = asset_fixture(asset.MetadataAssetLaunchingTestCase)
bootstrap = asset_fixture(asset.BootstrapAssetLaunchingTestCase)
cluster = asset_fixture(asset.ClusterAssetLaunchingTestCase)

mark_logs = enable_mark_logs_fixture()


@pytest.fixture(scope="session")
def browser_type_launch_args(
    browser_type_launch_args: dict,
):
    return {
        **browser_type_launch_args,
        'args': ["--host-resolver-rules=MAP *.wazo.local 127.0.0.1"],
    }
