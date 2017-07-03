#!/usr/bin/env python

import MySQLdb as mdb
import vspk.v4_0 as vspk
import logging
from keystoneauth1 import session
from keystoneauth1.identity import v3 as identity
from keystoneclient.v3 import client as keystone_client
from neutronclient.v2_0 import client as neutron_client
from netaddr import IPAddress, IPNetwork, AddrFormatError


class Sync:
    def __init__(self, config):
        self.cfg = config
        self.logger = logging.getLogger('nuage-neutron-sync')

        # Initialising
        self.neutron = None
        self.keystone = None
        self.vsd_user = None
        self.mysql_con = None

        self.set_up_connections()

    def set_up_connections(self):
        auth = identity.Password(**self.cfg.get_keystone_creds())
        sess = session.Session(auth=auth)
        self.neutron = neutron_client.Client(session=sess)
        self.keystone = keystone_client.Client(session=sess)
        # Set up connection to the VSD
        vsd_session = vspk.NUVSDSession(**self.cfg.get_vsd_creds())
        vsd_session.start()
        self.vsd_user = vsd_session.user
        self.mysql_con = mdb.connect(self.cfg.get_value('db_neutron', 'db_hostname'),
                                     self.cfg.get_value('db_neutron', 'db_username'),
                                     self.cfg.get_value('db_neutron', 'db_password'),
                                     self.cfg.get_value('db_neutron', 'db_name'))

    def is_excluded_project(self, project):
        excluded_enterprises = self.cfg.get_excluded_enterprise_names()
        if project.name in excluded_enterprises:
            return True
        return False

    # Sync all projects with the same name in VSD and OpenStack
    def get_tenants_to_sync(self):
        tenants_to_sync = []
        projects = self.keystone.projects.list()
        for project in projects:
            if not self.is_excluded_project(project):
                ent = self.vsd_user.enterprises.get_first(filter="name=='" + project.name + "'")
                if ent is not None:
                    tenants_to_sync.append((ent, project))
        return tenants_to_sync

    def get_current_subnet_mappings(self, net_partition_id):
        query = "SELECT subnet_id, nuage_subnet_id FROM nuage_subnet_l2dom_mapping where net_partition_id = '{0}'" \
            .format(net_partition_id)

        cur = self.mysql_con.cursor(mdb.cursors.DictCursor)
        cur.execute(query)
        rows = cur.fetchall()
        self.mysql_con.commit()  # commit to avoid caching the result of this query

        # The mysql result is a tuple of dictionaries
        # Convert this to one dictionary with key=nuage_subnet_id and value=subnet_id
        mappings = {}
        for subnet in rows:
            mappings[subnet['nuage_subnet_id']] = subnet['subnet_id']
        return mappings

    def calc_subnetname(self, nuage_subnet):
        if nuage_subnet.parent_type == "enterprise":
            net_name = self.calc_l2_subnetname(nuage_subnet)
        else:
            net_name = self.calc_l3_subnetname(nuage_subnet)
        return net_name

    def calc_l2_subnetname(self, nuage_l2domain):
        name = self.cfg.get_l2_name_format()
        name = name.replace('$d', nuage_l2domain.name)
        return name

    def calc_l3_subnetname(self, nuage_subnet):
        zone = vspk.NUZone(id=nuage_subnet.parent_id)
        zone.fetch()
        domain = vspk.NUDomain(id=zone.parent_id)
        domain.fetch()
        l3_name_format = self.cfg.get_l3_name_format()
        name = l3_name_format
        name = name.replace('$s', nuage_subnet.name)
        name = name.replace('$d', domain.name)
        name = name.replace('$z', zone.name)

        return name

    @staticmethod
    def net_nm_sanitizer(net, nm):
        return "{0}/{1}".format(net, str(IPAddress(nm).netmask_bits()))

    # calculate address, netmask and gateway to be used
    def get_cidr_and_gateway(self, nuage_subnet):
        if nuage_subnet.associated_shared_network_resource_id is not None:
            # shared subnet
            shared_network = vspk.NUSharedNetworkResource(id=nuage_subnet.associated_shared_network_resource_id)
            shared_network.fetch()
            if shared_network.type == "PUBLIC":
                # shared L3 subnet
                address = shared_network.address
                netmask = shared_network.netmask
                gateway = shared_network.gateway
                enable_dhcp = True
            else:
                # shared L2 subnet
                if shared_network.dhcp_managed:
                    enable_dhcp = True
                    address = shared_network.address
                    netmask = shared_network.netmask
                else:
                    address = self.cfg.get_unmanaged_networks_subnet()
                    netmask = self.cfg.get_unmanaged_networks_netmask()
                    enable_dhcp = False
                # gateway = None if dhcp option does not exist
                gateway = shared_network.dhcp_options.get_first(filter="type=='03'")
        elif nuage_subnet.parent_type != "enterprise":
            # L3 subnet
            address = nuage_subnet.address
            netmask = nuage_subnet.netmask
            gateway = nuage_subnet.gateway
            enable_dhcp = True
        elif nuage_subnet.dhcp_managed is True:
            # managed L2 (dhcp_managed attribute only exist for l2domain)
            address = nuage_subnet.address
            netmask = nuage_subnet.netmask
            # gateway = None if dhcp option does not exist
            gateway = nuage_subnet.dhcp_options.get_first(filter="type=='03'")
            enable_dhcp = True
        else:
            # unmanaged L2
            address = self.cfg.get_unmanaged_networks_subnet()
            netmask = self.cfg.get_unmanaged_networks_netmask()
            gateway = None
            enable_dhcp = False

        # generate subnet
        cidr = self.net_nm_sanitizer(address, netmask)

        if cidr == self.cfg.get_unmanaged_networks_cidr():
            metadata_cidr = nuage_subnet.metadatas.get_first(filter="name==cidr")
            if metadata_cidr is not None:
                # cidr is defined as metadata in the subnet
                try:
                    # Check if it is a valid network, throws error if wrong
                    ntw = IPNetwork(metadata_cidr.blob)
                    # If cidr would be 192.168.0.2/24, this will return 192.168.0.0/24
                    cidr = str(ntw.cidr)
                except AddrFormatError as e:
                    self.logger.error("Invalid cidr ({0}) set in metadata of nuage subnet {1}. Ignoring"
                                      .format(metadata_cidr.blob, nuage_subnet.id))
                    self.logger.error(str(e))
        return cidr, gateway, enable_dhcp

    def add_neutron_subnet(self, nuage_subnet, project, enterprise):
        net_name = self.calc_subnetname(nuage_subnet)

        # create network
        body_nw = {
            "network":
                {
                    "name": net_name,
                    "admin_state_up": True,
                    "tenant_id": project.id
                }
        }
        try:
            self.logger.debug("Creating network with body {0}".format(body_nw))
            network = self.neutron.create_network(body=body_nw)
        except Exception as e:
            self.logger.error("Error creating neutron network {0}".format(body_nw))
            self.logger.error(str(e))
            return

        cidr, gateway, enable_dhcp = self.get_cidr_and_gateway(nuage_subnet)

        body_subnet = {
            "subnets": [
                {
                    "name": net_name,
                    "cidr": cidr,
                    "ip_version": 4,
                    "network_id": network['network']['id'],
                    "nuagenet": nuage_subnet.id,
                    "net_partition": enterprise.name,
                    "tenant_id": project.id
                }
            ]
        }

        body_subnet['subnets'][0]['enable_dhcp'] = enable_dhcp

        if gateway is not None:
            body_subnet['subnets'][0]['gateway_ip'] = gateway

        try:
            self.logger.debug("Creating subnet with body {0}".format(body_subnet))
            self.neutron.create_subnet(body=body_subnet)
            self.logger.info("Created neutron subnet {0}".format(net_name))
        except Exception as e:
            self.logger.error("Error creating neutron subnet {0}".format(body_subnet))
            self.logger.error(str(e))
            self.neutron.delete_network(network['network']['id'])

    def del_neutron_network(self, openstack_subnet_id):
        subnet = self.neutron.show_subnet(openstack_subnet_id)['subnet']
        # Subnet will be removed if network is removed
        self.neutron.delete_network(subnet['network_id'])

    def check_if_correct(self, nuage_subnet, openstack_subnet_id):
        if nuage_subnet.parent_type != "enterprise" and nuage_subnet.address is None \
                and nuage_subnet.associated_shared_network_resource_id is None:
            self.logger.debug("VSD subnet {0} is a shared L3 subnet without the subnet attached. Ignoring."
                              .format(nuage_subnet.id))
            return False

        mapping_correct = True
        openstack_subnet = self.neutron.show_subnet(openstack_subnet_id)['subnet']

        subnet_name = self.calc_subnetname(nuage_subnet)
        if subnet_name != openstack_subnet['name']:
            mapping_correct = False
            self.logger.debug("VSD subnet {0} was renamed from \"{0}\" to \"{1}\"".format(nuage_subnet.id,
                                                                                          openstack_subnet['name'],
                                                                                          subnet_name))

        cidr, gateway, enable_dhcp = self.get_cidr_and_gateway(nuage_subnet)
        if enable_dhcp != openstack_subnet['enable_dhcp']:
            mapping_correct = False
            self.logger.debug("DHCP not correct in subnet {0} (\"{1}\")".format(nuage_subnet.id, subnet_name))

        if openstack_subnet['gateway_ip'] != gateway:
            mapping_correct = False
            self.logger.debug("Gateway IP of subnet {0} (\"{1}\") changed to {2}".
                              format(nuage_subnet.id, subnet_name, gateway))

        if cidr != openstack_subnet['cidr']:
            self.logger.debug("CIDR of subnet {0} (\"{1}\") changed to {2}".format(nuage_subnet.id, subnet_name, cidr))
            mapping_correct = False

        return mapping_correct

    def sync_once(self):
        for t in self.get_tenants_to_sync():
            enterprise, project = t
            self.sync_once_enterprise(enterprise, project)

    def sync_once_enterprise(self, enterprise, project):
        self.logger.debug("start syncing enterprise {0}".format(enterprise.name))
        subnet_mappings = self.get_current_subnet_mappings(enterprise.id)
        # L3 domains
        for domain in enterprise.domains.get():
            for nuage_subnet in domain.subnets.get():
                self.sync_subnet(enterprise, nuage_subnet, project, subnet_mappings)
        for nuage_subnet in enterprise.l2_domains.get():
            self.sync_subnet(enterprise, nuage_subnet, project, subnet_mappings)

        # all remaining subnet mappings do not exist in VSD anymore, delete neutron subnets
        for openstack_subnet_id in subnet_mappings.itervalues():
            self.logger.info("OpenStack subnet {0} does not exist anymore in VSD. Deleting..."
                             .format(openstack_subnet_id))
            try:
                self.del_neutron_network(openstack_subnet_id)
            except Exception as e:
                self.logger.error("Unable to delete network {0}".format(openstack_subnet_id))
                self.logger.error(str(e))

    def sync_subnet(self, enterprise, nuage_subnet, project, subnet_mappings):
        # Ignore shared subnets if not enabled in the configuration file
        if nuage_subnet.associated_shared_network_resource_id is not None and \
                not self.cfg.get_boolean('sync', 'sync_shared_subnets'):
            self.logger.debug("Ignoring vsd subnet {0}. Sync of shared subnets is disabled in configuration.".format(
                nuage_subnet.id))
            return

        # ignore L3 shared subnet with nothing attached
        if nuage_subnet.parent_type != "enterprise" and nuage_subnet.address is None \
                and nuage_subnet.associated_shared_network_resource_id is None:
            if self.cfg.get_boolean('sync', 'sync_shared_subnets'):
                self.logger.debug("Ignoring vsd subnet {0}. Sync of shared subnets is disabled in configuration."
                                  .format(nuage_subnet.id))
            else:
                self.logger.info("vsd subnet {0} is a shared L3 subnet without the subnet attached. Ignoring")
            return

        synced = False
        if nuage_subnet.id in subnet_mappings:
            synced = True
            if self.check_if_correct(nuage_subnet, subnet_mappings[nuage_subnet.id]) is False:
                try:
                    self.logger.info("VSD subnet {0} has changed. Deleting mapped OpenStack subnet {1}"
                                     .format(nuage_subnet.id, subnet_mappings[nuage_subnet.id]))
                    self.del_neutron_network(subnet_mappings[nuage_subnet.id])
                except Exception as e:
                    self.logger.error("Unable to delete OpenStack subnet {0}"
                                      .format(subnet_mappings[nuage_subnet.id]))
                    self.logger.error(str(e))
                else:
                    synced = False
            else:
                self.logger.debug("VSD subnet {0} is correctly mapped to OpenStack subnet {1}".
                                  format(nuage_subnet.id, subnet_mappings[nuage_subnet.id]))
            # mapping is either correct or not relevant anymore, delete item from dictionary
            # all remaining items in subnet_mappings will be deleted
            del subnet_mappings[nuage_subnet.id]
        if synced is False:
            # Create network in OpenStack
            self.add_neutron_subnet(nuage_subnet, project, enterprise)
