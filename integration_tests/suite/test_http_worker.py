# Copyright 2026 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import time

import requests
from wazo_test_helpers import until

from .helpers import base


@base.use_asset('base')
class TestHttpWorker(base.APIIntegrationTest):
    def test_requests_are_load_balanced_across_primary_and_worker(self):
        url = f'http://127.0.0.1:{self.auth_port()}/0.1/backends'

        def both_instances_served():
            requests.get(url, headers={'Connection': 'close'})
            return all(
                '/0.1/backends' in self.service_logs(service_name)
                for service_name in ('auth', 'auth-worker')
            )

        until.true(
            both_instances_served,
            timeout=30,
            message='Requests were not load-balanced across both instances',
        )

    def test_only_the_primary_runs_the_expired_token_remover(self):
        def primary_ran_remover():
            return 'ExpiredTokenRemover took' in self.service_logs('auth')

        until.true(
            primary_ran_remover,
            timeout=30,
            message='The primary never ran the ExpiredTokenRemover',
        )

        worker_logs = self.service_logs('auth-worker')
        assert 'ExpiredTokenRemover took' not in worker_logs

    def test_restarting_auth_also_cycles_the_worker(self):
        self.restart_auth()
        restarted_at = time.time()
        url = f'http://127.0.0.1:{self.auth_port()}/0.1/backends'

        def both_instances_served_after_restart():
            requests.get(url, headers={'Connection': 'close'})
            return all(
                '/0.1/backends' in self.service_logs(service_name, since=restarted_at)
                for service_name in ('auth', 'auth-worker')
            )

        until.true(
            both_instances_served_after_restart,
            timeout=30,
            message='auth-worker did not resume serving after auth was restarted',
        )
