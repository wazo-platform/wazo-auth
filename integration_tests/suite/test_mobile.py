# Copyright 2019-2024 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import requests
from hamcrest import (
    assert_that,
    calling,
    has_entries,
    has_entry,
    has_properties,
    has_property,
)
from wazo_test_helpers.hamcrest.raises import raises

from .helpers import base, fixtures

TENANT_UUID = 'ad235675-053d-482a-9e07-6d36de6a48b5'


@base.use_asset('external_auth')
class TestExternalAuthMobile(base.ExternalAuthIntegrationTest):
    EXTERNAL_AUTH_TYPE = 'mobile'
    SECRET = {
        'fcm_api_key': 'fcm_api_key',
        'fcm_sender_id': 'fcm_sender_id',
        'ios_apn_certificate': 'ios_apn_private',
        'use_sandbox': True,
    }

    def tearDown(self):
        try:
            self.client.external.delete_config(self.EXTERNAL_AUTH_TYPE)
        except requests.HTTPError:
            pass

    @fixtures.http.tenant(uuid=TENANT_UUID)
    @fixtures.http.user(username='one', password='pass', tenant_uuid=TENANT_UUID)
    @fixtures.http.token(username='one', password='pass', expiration=30)
    def test_mobile_workflow(self, tenant, user, token):
        self.client.tenant_uuid = tenant['uuid']
        self.client.external.create_config(
            auth_type=self.EXTERNAL_AUTH_TYPE, data=self.SECRET
        )

        response = self.client.external.get_config(self.EXTERNAL_AUTH_TYPE)
        assert_that(response, has_entries(self.SECRET))

        self.client.set_token(token['token'])

        assert_that(
            calling(self.client.external.get).with_args(
                self.EXTERNAL_AUTH_TYPE, user['uuid']
            ),
            raises(requests.HTTPError).matching(
                has_property('response', has_properties(status_code=404))
            ),
        )

        response = self.client.external.create(
            self.EXTERNAL_AUTH_TYPE,
            user['uuid'],
            {
                'token': 'TOKEN',
                'apns_token': 'APNS_VOIP_TOKEN',
                'apns_voip_token': 'APNS_VOIP_TOKEN',
                'apns_notification_token': 'APNS_NOTIFICATION_TOKEN',
            },
        )
        assert_that(
            response,
            has_entries(
                token='TOKEN',
                apns_token='APNS_VOIP_TOKEN',
                apns_voip_token='APNS_VOIP_TOKEN',
                apns_notification_token='APNS_NOTIFICATION_TOKEN',
            ),
        )
        response = self.client.external.get(self.EXTERNAL_AUTH_TYPE, user['uuid'])
        assert_that(
            response,
            has_entries(
                token='TOKEN',
                apns_token='APNS_VOIP_TOKEN',
                apns_voip_token='APNS_VOIP_TOKEN',
                apns_notification_token='APNS_NOTIFICATION_TOKEN',
            ),
        )

        response = self.get_sender_id(user)
        assert_that(response, has_entry('sender_id', 'fcm_sender_id'))

        self.client.external.delete(self.EXTERNAL_AUTH_TYPE, user['uuid'])
        assert_that(
            calling(self.client.external.get).with_args(
                self.EXTERNAL_AUTH_TYPE, user['uuid']
            ),
            raises(requests.HTTPError).matching(
                has_property('response', has_properties(status_code=404))
            ),
        )

    def get_sender_id(self, user):
        # NOTE(sileht): client doesn't have this endpoints has its specific to
        # android application
        headers = self.client.external._get_headers()
        base_url = self.client.external._build_url(
            self.EXTERNAL_AUTH_TYPE, user['uuid']
        )
        url = f'{base_url}/sender_id'
        r = self.client.external.session.get(url, headers=headers)
        if r.status_code != 200:
            self.client.external.raise_from_response(r)

        return r.json()
