# Copyright 2023 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from wazo_auth.http import Resource


class MetricResource(Resource):
    def get(self):
        return {"it": "works"}
