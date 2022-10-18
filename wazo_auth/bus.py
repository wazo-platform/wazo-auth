# Copyright 2017-2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

from xivo_bus.publisher import BusPublisher as Publisher


class BusPublisher(Publisher):
    @classmethod
    def from_config(cls, service_uuid, bus_config):
        return cls(name='wazo-auth', service_uuid=service_uuid, **bus_config)
