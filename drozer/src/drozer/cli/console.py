#!/usr/bin/python

import logging
import sys

from mwr.common import logger

from drozer.console import Console

logger.setLevel(logging.DEBUG)
logger.addStreamHandler()
argv = ["connect"]
Console().run(argv)
