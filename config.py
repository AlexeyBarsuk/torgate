#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging

TEMP_DIR_PATH = '/tmp/torgate'
TOR_EXECUTABLE_PATH = 'tor'

PROXIES_COUNT = 10
PROXIES_FILENAME = "/tmp/listeners.txt"
LISTEN_INTERFACE = '127.0.0.1'
PORT_RANGE_START = 20000
PORT_RANGE_END = 30000

LOGLEVEL = logging.INFO
