# Copyright 2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo.status import Status

from wazo_auth.http import ErrorCatchingResource


class StatusList(ErrorCatchingResource):
    def __init__(self, status_aggregator):
        self.status_aggregator = status_aggregator

    def head(self):
        for component in self.status_aggregator.status().values():
            if component.get('status') == Status.fail:
                return '', 503
        return '', 200
