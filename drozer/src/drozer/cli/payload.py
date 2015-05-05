#!/usr/bin/python

import logging
import sys

from mwr.common import logger

from drozer.payload.manager import PayloadManager

logger.setLevel(logging.DEBUG)
logger.addStreamHandler()
args = ["build", "weasel.shell.armeabi",  "--server", "127.0.0.1:31415"]
PayloadManager().run(args)
