# -*- coding: utf-8 -*-
# Copyright 2017 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+

import logging

from contextlib import contextmanager
from threading import Thread
from kombu import Connection
from kombu import Exchange
from kombu import Producer
from xivo_bus import Marshaler
from xivo_bus import Publisher
from xivo_bus import PublishingQueue

logger = logging.getLogger(__name__)


@contextmanager
def publisher_thread(publisher):
    thread_name = 'bus_publisher_thread'
    thread = Thread(target=publisher.run, name=thread_name)
    thread.start()
    try:
        yield
    finally:
        logger.debug('stopping bus producer thread')
        publisher.stop()
        logger.debug('joining bus producer thread')
        thread.join()


class BusPublisher(object):

    def __init__(self, global_config):
        self.config = global_config['amqp']
        self._uuid = global_config['uuid']
        self._publisher = PublishingQueue(self._make_publisher)

    def run(self):
        logger.info("Running AMQP publisher")

        self._publisher.run()

    def _make_publisher(self):
        bus_url = self.config['uri']
        bus_connection = Connection(bus_url)
        bus_exchange = Exchange(self.config['exchange_name'], type=self.config['exchange_type'])
        bus_producer = Producer(bus_connection, exchange=bus_exchange, auto_declare=True)
        bus_marshaler = Marshaler(self._uuid)
        return Publisher(bus_producer, bus_marshaler)

    def publish(self, event, headers=None):
        logger.debug('Publishing event "%s": %s', event.name, event.marshal())
        self._publisher.publish(event, headers)

    def stop(self):
        self._publisher.stop()
