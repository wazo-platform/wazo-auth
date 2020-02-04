# Copyright 2020 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from unittest import TestCase

from ..flask import extract_connection_params


class TestExtractConnectionParams(TestCase):
    def test_host_port(self):
        headers = {'Host': 'my-host-0:9497'}

        result = extract_connection_params(headers)

        assert result['hostname'] == 'my-host-0'
        assert result['port'] == 9497

    def test_host_no_port(self):
        headers = {'Host': 'my-host-0'}

        result = extract_connection_params(headers)

        assert result['hostname'] == 'my-host-0'
        assert 'port' not in result

    def test_ipv4_port(self):
        headers = {'Host': '192.168.1.1:9497'}

        result = extract_connection_params(headers)

        assert result['hostname'] == '192.168.1.1'
        assert result['port'] == 9497

    def test_ipv4_no_port(self):
        headers = {'Host': '192.168.1.1'}

        result = extract_connection_params(headers)

        assert result['hostname'] == '192.168.1.1'
        assert 'port' not in result

    def test_ipv6_port(self):
        headers = {'Host': '[::1]:9497'}

        result = extract_connection_params(headers)

        assert result['hostname'] == '::1'
        assert result['port'] == 9497

    def test_ipv6_no_port(self):
        headers = {'Host': '[::1]'}

        result = extract_connection_params(headers)

        assert result['hostname'] == '::1'
        assert 'port' not in result

    def test_prefix_and_port(self):
        headers = {'Host': '[::1]:443', 'X-Script-Name': '/api/auth'}

        result = extract_connection_params(headers)

        assert result['hostname'] == '::1'
        assert result['port'] == 443
        assert result['prefix'] == '/api/auth'
