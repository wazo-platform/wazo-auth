# Copyright 2017-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo_bus.publisher import BusPublisher as Publisher


class BusPublisher(Publisher):
    def __init__(self, service_uuid=None, **kwargs):
        name = 'wazo-auth'
        self._url = kwargs.pop('uri', None)
        super().__init__(name, service_uuid, **kwargs)

    @classmethod
    def from_config(cls, service_uuid, bus_config):
        return cls(service_uuid=service_uuid, **bus_config)

    @property
    def url(self):
        return self._url
