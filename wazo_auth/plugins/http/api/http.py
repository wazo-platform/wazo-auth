# Copyright 2017-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from itertools import chain

import yaml
from flask import make_response
from flask_restful import Resource
from xivo.chain_map import ChainMap
from xivo.http_helpers import reverse_proxy_fix_api_spec
from xivo.rest_api_helpers import load_all_api_specs


class Swagger(Resource):
    api_filename = "api.yml"

    def get(self):
        http_specs = load_all_api_specs('wazo_auth.http', self.api_filename)
        external_auth_specs = load_all_api_specs(
            'wazo_auth.external_auth', self.api_filename
        )
        specs = chain(http_specs, external_auth_specs)

        api_spec = ChainMap(*specs)
        if not api_spec.get('info'):
            return {'error': "API spec does not exist"}, 404

        reverse_proxy_fix_api_spec(api_spec)
        return make_response(
            yaml.dump(dict(api_spec)), 200, {'Content-Type': 'application/x-yaml'}
        )
