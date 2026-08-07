# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from datetime import datetime, timezone

from wazo_test_helpers import until

from .helpers import base

AUTH_SERVICES = ('auth', 'auth2')
LEADER_ACQUIRED = 'acquired the wazo-auth scheduler leader lock'
ONE_SHOT_CRASHES = ('DuplicatePolicyException', 'DuplicateGroupException')

USERNAME = 'admin'
PASSWORD = 's3cre7'


@base.use_asset('cluster')
class TestCluster(unittest.TestCase):
    asset_cls = base.ClusterAssetLaunchingTestCase

    @classmethod
    def _leader_counts(cls):
        return {
            service: cls.asset_cls.service_logs(service).count(LEADER_ACQUIRED)
            for service in AUTH_SERVICES
        }

    def test_cold_start_has_no_one_shot_crashes(self):
        for service in AUTH_SERVICES:
            logs = self.asset_cls.service_logs(service)
            for crash in ONE_SHOT_CRASHES:
                assert crash not in logs, f'{crash} found in {service} logs'

    def test_api_serves_on_both_instances(self):
        clients = {
            service: self.asset_cls.make_auth_client(
                USERNAME, PASSWORD, service_name=service
            )
            for service in AUTH_SERVICES
        }

        tokens = {
            service: client.token.new(expiration=60)['token']
            for service, client in clients.items()
        }

        # replicas share the database: a token created on one instance must
        # be valid on the other
        assert clients['auth2'].token.is_valid(tokens['auth'])
        assert clients['auth'].token.is_valid(tokens['auth2'])

    def test_exactly_one_scheduler_leader(self):
        until.true(
            lambda: sum(self._leader_counts().values()) >= 1,
            timeout=15,
            interval=1,
        )

        assert sum(self._leader_counts().values()) == 1

    def test_zz_leader_failover(self):
        # named to run last: it stops a container
        until.true(
            lambda: sum(self._leader_counts().values()) >= 1,
            timeout=15,
            interval=1,
        )
        counts = self._leader_counts()
        leader = max(counts, key=counts.get)
        survivor = next(s for s in AUTH_SERVICES if s != leader)
        since = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        self.asset_cls.stop_service(leader)
        self.addCleanup(self._restart_instance, leader)

        until.true(
            lambda: LEADER_ACQUIRED
            in self.asset_cls.service_logs(survivor, since=since),
            timeout=30,
            interval=1,
        )

    def _restart_instance(self, service):
        self.asset_cls.start_service(service)
        auth = self.asset_cls.make_auth_client(service_name=service)
        until.return_(auth.status.check, timeout=30)
