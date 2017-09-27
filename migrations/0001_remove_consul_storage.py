#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2016-2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

from consul import Consul

from xivo.config_helper import read_config_file_hierarchy

DEFAULT_CONFIG = {
    'config_file': '/etc/wazo-auth/config.yml',
    'extra_config_files': '/etc/wazo-auth/conf.d',
}
STORAGE = 'xivo/xivo-auth'


def main():
    print 'Removing data from consul...'
    consul_config = read_config_file_hierarchy(DEFAULT_CONFIG)['consul']
    client = Consul(**consul_config)
    client.kv.delete(STORAGE, recurse=True)
    print 'done'


if __name__ == '__main__':
    main()
