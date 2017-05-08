#!/usr/bin/python
"""
Usage:
  nuage-neutron-sync sync [--once] [options]
  nuage-neutron-sync vsdmanaged-tenant (create|delete) <name> [options]
  nuage-neutron-sync vsdmanaged-tenant list [options]
  nuage-neutron-sync (-h | --help)

Options:
  -h --help              Show this screen
  -v --version           Show version
  --log-file=<file>      Log file location
  --config-file=<file>   Configuration file location [default: /etc/nuage-neutron-sync/nuage-neutron-sync.conf]
Sync Options:
  --once                 Run the sync only once
"""


from utils import config
from utils import log
from docopt import docopt
from operations import sync, tenant
import time
import sys


def getargs():
    return docopt(__doc__, version="nuage-neutron-sync 1.0.0")


def execute():
    main(getargs())

 
def main(args):
    logger = log.start_logging()

    try:
        cfg = config.Config(args['--config-file'], logger)
    except Exception, e:
        logger.error("Error reading config file from location: {0}".format(args['--config-file']))
        logger.error(str(e))
        sys.exit(1)

    if args['--log-file']:
        try:
            log.setlogpath(args['--log-file'], cfg)
        except Exception, e:
            logger.error("Cannot set log location: {0}".format(args['--log-file']))
            logger.error(str(e))
            sys.exit(1)

    # set loglevel
    try:
        log.setloglevel(cfg.get_log_level())
    except Exception, e:
        logger.error("Error setting logging level to {0}".format(cfg.get_value('logging', 'loglevel')))
        logger.error(str(e))

    if args['sync']:
        s = sync.Sync(cfg)
        if args['--once']:
            s.sync_once()
        else:
            interval = cfg.get_value('sync', 'interval')
            if type(interval) != int:
                interval = 10
            while True:
                # Catch whatever Exception you have during sync.
                # Errors are most likely related to timeouts on one of the existing connections (vsd/neutron/...).
                # Recreate the connections and restart.
                # If no error, wait <interval> seconds, otherwise, wait just one second and restart.
                try:
                    s.sync_once()
                except Exception as e:
                    logger.error("Error during syncing")
                    logger.error(str(e))
                    logger.info("Set up connections")
                    s.set_up_connections()
                    time.sleep(1)
                else:
                    time.sleep(interval)

    # Only for Monolithic plugin!
    elif args['vsdmanaged-tenant']:
        t = tenant.Tenant(cfg)
        if args['create']:
            t.create_vsd_managed_tenant(args['<name>'])
        elif args['delete']:
            s = sync.Sync(cfg)
            t.delete_vsd_managed_tenant(args['<name>'], s)
        elif args['list']:
            t.list_vsd_managed_tenants()


if __name__ == "__main__":
    main(getargs())
