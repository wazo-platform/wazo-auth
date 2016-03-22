#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2016 by Avencall
# SPDX-License-Identifier: GPL-3.0+

from consul import Consul

from xivo.config_helper import read_config_file_hierarchy

DEFAULT_CONFIG = {
    'config_file': '/etc/xivo-auth/config.yml',
    'extra_config_files': '/etc/xivo-auth/conf.d',
}
NAMED_TOKENS = 'xivo/xivo-auth/token-names'


def main():
    print 'Removing named tokens from consul...'
    consul_config = read_config_file_hierarchy(DEFAULT_CONFIG)['consul']
    client = Consul(**consul_config)
    client.kv.delete(NAMED_TOKENS, recurse=True)
    print 'done'


if __name__ == '__main__':
   main()
