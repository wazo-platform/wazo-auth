# Copyright 2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from prometheus_flask_exporter import PrometheusMetrics


class Plugin:
    def load(self, dependencies):
        api = dependencies['api']

        self.metrics = PrometheusMetrics(api.app, path=f'{api.prefix}/metrics')
