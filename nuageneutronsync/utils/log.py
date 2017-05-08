#!/usr/bin/env python

import logging
import logging.handlers
import sys
import os

LEVELS = {'debug': logging.DEBUG,
          'info': logging.INFO,
          'warning': logging.WARNING,
          'error': logging.ERROR,
          'critical': logging.CRITICAL}


def setlogpath(path, config):
    logger = logging.getLogger('nuage-neutron-sync')

    if not os.path.exists(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path))

    enable_rotate, maxsize, backups = config.get_log_config()
    if enable_rotate:
        fileh = logging.handlers.RotatingFileHandler(path, 'a', maxBytes=maxsize * 1000000, backupCount=backups)
    else:
        fileh = logging.FileHandler(path, 'a')

    formatter = logging.Formatter("%(asctime)s:%(levelname)s:%(name)s:%(message)s")
    fileh.setFormatter(formatter)
    for hdlr in logger.handlers:
        logger.removeHandler(hdlr)
    logger.addHandler(fileh)
    logger.propagate = False


def setloglevel(log_level):
    logger = logging.getLogger('nuage-neutron-sync')
    parsed_log_level = LEVELS.get(log_level.lower(), logging.NOTSET)
    if not parsed_log_level:
        raise ValueError('Invalid log level: {0}'.format(log_level))
    logger.info("Loglevel set to {0}".format(log_level))
    logger.setLevel(parsed_log_level)


def start_logging():
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    logger = logging.getLogger('nuage-neutron-sync')
    logger.info("Logging started with logging level INFO")

    # Suppress INFO messages from Bambou
    l = logging.getLogger('bambou')
    l.setLevel(logging.WARN)

    return logger
