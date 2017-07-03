#!/usr/bin/env python

import ConfigParser
import os
from netaddr import IPNetwork, AddrFormatError


class Config:
    def __init__(self, path, logger):
        if not os.path.isfile(path):
            raise ValueError('Invalid config file: {0}'.format(path))
        logger.info("Reading config file from {0}".format(path))

        self.cfg = ConfigParser.ConfigParser()
        self.cfg.read(path)

    def get_value(self, section, name):
        return self.cfg.get(section, name)

    def get_boolean(self, section, name):
        return self.cfg.getboolean(section, name)

    def get_log_config(self):
        # default values
        enable_rotate = False
        maxsize = 10
        backups = 5
        if self.cfg.has_section('logging'):
            if self.cfg.has_option('logging', 'rotate_logfiles'):
                enable_rotate = self.cfg.getboolean('logging', 'rotate_logfiles')
                if enable_rotate:
                    if self.cfg.has_option('logging', 'maxsize'):
                        maxsize = int(self.cfg.get('logging', 'maxsize'))
                    if self.cfg.has_option('logging', 'backups'):
                        backups = int(self.cfg.get('logging', 'backups'))
        return enable_rotate, maxsize, backups

    def get_keystone_creds(self):
        return {'auth_url': self.get_value('openstack', 'auth_url'),
                'username': self.get_value('openstack', 'admin_username'),
                'password': self.get_value('openstack', 'admin_password'),
                'project_name': self.get_value('openstack', 'project_name'),
                'project_domain_id': self.get_value('openstack', 'project_domain_id'),
                'user_domain_id': self.get_value('openstack', 'user_domain_id')
                }

    def get_vsd_creds(self):
        return {'username': self.get_value('vsd', 'username'),
                'certificate': (self.get_value('vsd', 'cert'), self.get_value('vsd', 'key')),
                'enterprise': self.get_value('vsd', 'enterprise'),
                'api_url': self.get_value('vsd', 'api_url')
                }

    def get_excluded_enterprise_names(self):
        excluded_enterprises = self.get_value('sync', 'excluded_enterprises').split(',')
        # remove spaces
        excluded_enterprises = [x.strip(' ') for x in excluded_enterprises]
        return excluded_enterprises

    def get_l2_name_format(self):
        if not self.cfg.has_option('sync', 'l2_name_format'):
            l2_name_format = "$d"
        else:
            l2_name_format = self.cfg.get('sync', 'l2_name_format')
        return l2_name_format

    def get_l3_name_format(self):
        if not self.cfg.has_option('sync', 'l3_name_format'):
            l3_name_format = "$d ($z) \ $s"
        else:
            l3_name_format = self.cfg.get('sync', 'l3_name_format')
        return l3_name_format

    def get_log_level(self):
        if self.cfg.has_option('logging', 'loglevel'):
            return self.cfg.get('logging', 'loglevel')
        else:
            return "INFO"

    def get_unmanaged_networks(self):
        if self.cfg.has_option('sync', 'unmanaged_networks_cidr'):
            try:
                ntw = IPNetwork(self.cfg.get('sync', 'unmanaged_networks_cidr'))
            except AddrFormatError:
                ntw = IPNetwork("127.0.0.0/8")
        else:
            ntw = IPNetwork("127.0.0.0/8")
        return ntw

    def get_unmanaged_networks_cidr(self):
        return str(self.get_unmanaged_networks().cidr)

    def get_unmanaged_networks_subnet(self):
        return str(self.get_unmanaged_networks().ip)

    def get_unmanaged_networks_netmask(self):
        return str(self.get_unmanaged_networks().netmask)
