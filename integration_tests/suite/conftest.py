# Copyright 2021-2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import pytest
from wazo_test_helpers.asset_launching_test_case import AssetLaunchingTestCase

from .helpers import base as asset

logger = logging.getLogger(__name__)

_teardowns: dict[str, Callable[[], None]] = {}
_teardown_failures: list[tuple[str, BaseException]] = []


def pytest_collection_modifyitems(session, config, items):
    # Group tests by their asset so each asset is set up/torn down once, in a
    # contiguous run (this also removes the run-order pytest feature --ff/--nf).
    items.sort(key=lambda item: _marker_of(item) or '')


def _marker_of(item) -> str | None:
    # The asset name is the argument of the `use_asset` (usefixtures) marker.
    # Find it explicitly rather than assuming it is the first/only class marker.
    parent = getattr(item, 'parent', None)
    for marker in getattr(parent, 'own_markers', []):
        if marker.name == 'usefixtures' and marker.args:
            return marker.args[0]
    return None


def _teardown(marker: str) -> None:
    teardown = _teardowns.get(marker)
    if teardown is not None:
        teardown()
        _teardowns.pop(marker, None)


@contextmanager
def managed_asset(request, asset_class: type[AssetLaunchingTestCase]) -> Iterator[None]:
    marker = request.fixturename
    asset_class.setUpClass()
    _teardowns[marker] = asset_class.tearDownClass
    try:
        yield
    finally:
        _teardown(marker)


@pytest.hookimpl(trylast=True)
def pytest_runtest_teardown(item, nextitem) -> None:
    # Eagerly tear down the active asset at marker-group boundaries; the
    # session-scoped fixture's finally still handles the very last asset.
    # Swallow errors here so a teardown failure can't abort the next test's
    # setup; the fixture-finally path lets exceptions propagate so they
    # surface in pytest's error summary.
    if nextitem is None:
        return
    current = _marker_of(item)
    upcoming = _marker_of(nextitem)
    if current is not None and current != upcoming:
        try:
            _teardown(current)
        except Exception as exc:
            logger.exception('Failed to tear down asset for marker %r', current)
            _teardown_failures.append((current, exc))


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:
    for marker, exc in _teardown_failures:
        terminalreporter.write_sep(
            '!', f'Asset teardown failed for marker {marker!r}: {exc}'
        )


@pytest.fixture(scope='session')
def base(request):
    with managed_asset(request, asset.APIAssetLaunchingTestCase):
        yield


@pytest.fixture(scope='session')
def saml(request):
    with managed_asset(request, asset.SAMLAssetLaunchingTestCase):
        yield


@pytest.fixture(scope='session')
def database(request):
    with managed_asset(request, asset.DBAssetLaunchingTestCase):
        yield


@pytest.fixture(scope='session')
def external_auth(request):
    with managed_asset(request, asset.ExternalAuthAssetLaunchingTestCase):
        yield


@pytest.fixture(scope='session')
def metadata(request):
    with managed_asset(request, asset.MetadataAssetLaunchingTestCase):
        yield


@pytest.fixture(scope='session')
def bootstrap(request):
    with managed_asset(request, asset.BootstrapAssetLaunchingTestCase):
        yield


@pytest.fixture(autouse=True, scope='function')
def mark_logs(request):
    test_name = f'{request.cls.__name__}.{request.function.__name__}'
    request.cls.asset_cls.mark_logs_test_start(test_name)
    yield
    request.cls.asset_cls.mark_logs_test_end(test_name)


@pytest.fixture(scope="session")
def browser_type_launch_args(
    browser_type_launch_args: dict,
):
    return {
        **browser_type_launch_args,
        'args': ["--host-resolver-rules=MAP *.wazo.local 127.0.0.1"],
    }
