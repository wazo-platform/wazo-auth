# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from xivo.consul_helpers import ServiceCatalogRegistration


class ServiceDiscoveryComponent:
    """start()/stop() wrapper around the ServiceCatalogRegistration context
    manager, so the controller can start it conditionally based on roles."""

    def __init__(self, *registration_args):
        self._registration_args = registration_args
        self._registration = None

    def start(self):
        registration = ServiceCatalogRegistration(*self._registration_args)
        registration.__enter__()
        # assigned only after a successful __enter__ so that stop() stays a
        # no-op when registration failed, like a raising `with` statement
        self._registration = registration

    def stop(self):
        registration, self._registration = self._registration, None
        if registration is not None:
            registration.__exit__(None, None, None)
