#!/usr/bin/env python

from time import sleep
import logging
from keystoneauth1 import session
from keystoneauth1.identity import v3 as identity
from keystoneclient.v3 import client as keystone_client
from neutronclient.v2_0 import client as neutron_client
from neutronclient.common.exceptions import NotFound as neutron_NotFound
from keystoneauth1.exceptions.http import NotFound as keystone_NotFound
from novaclient import client as nova_client
from prettytable import PrettyTable
import sys
import importlib

vspk = None


class Tenant:
    def __init__(self, config):
        self.cfg = config
        self.logger = logging.getLogger('nuage-neutron-sync')

        self.version = self.cfg.get_value('vsd', 'version')
        try:
            global vspk
            vspk = importlib.import_module('vspk.{0:s}'.format(self.version))
        except ImportError as e:
            self.logger.error("Invalid VSPK version")
            self.logger.error(str(e))
            sys.exit('Invalid VSPK version')

        auth = identity.Password(**self.cfg.get_keystone_creds())
        sess = session.Session(auth=auth)
        self.neutron = neutron_client.Client(session=sess)
        self.keystone = keystone_client.Client(session=sess)
        self.nova = nova_client.Client(2, session=sess)

        # Set up connection to the VSD
        vsd_session = vspk.NUVSDSession(**self.cfg.get_vsd_creds())
        vsd_session.start()
        self.vsd_user = vsd_session.user

    def keystone_tenant_exists(self, tenant_name):
        try:
            if self.keystone.projects.find(name="{0}".format(tenant_name)):
                return True
            else:
                return False
        except:
            return False

    def netpartition_exists(self, tenant_name):
        if self.neutron.list_net_partitions(name=tenant_name)['net_partitions'][0]:
            return True
        else:
            return False

    def delete_vms_in_tenant(self, tenant):
        # Get VMs created by this tenant. Both options "all_tenants" and "tenant_id" should be set
        servers = self.nova.servers.list(search_opts={'all_tenants': 1, 'tenant_id': tenant.id})
        for server in servers:
            self.logger.info("Deleting VM: {0}".format(server.id))
            try:
                server.delete()
            except:
                self.logger.error("Cannot delete VM: {0}".format(server['id']))

        # Wait until servers are gone and return
        for i in range(0, 20):
            servers = self.nova.servers.list(search_opts={'all_tenants': 1, 'tenant_id': tenant.id})
            if not servers:
                return
            else:
                self.logger.info("Servers not yet deleted, waiting")
                sleep(1)

        self.logger.error("Error deleting servers")
        raise NotImplementedError

    def delete_vsdobjects_in_tenant(self, enterprise):
        self.logger.info("Deleting all VSD objects for tenant: {0}".format(enterprise.name))

        # Get and delete all the active domains in the enterprise
        try:
            domains = enterprise.domains.get()
            # Delete each L3 domain
            for domain in domains:
                self.delete_vsd_domain(domain)
        except Exception, e:
            self.logger.error("VSD - while deleting domains")
            self.logger.error(repr(e))
            return 1

        # Get and delete all the active l2domains in the enterprise
        try:
            domains = enterprise.l2_domains.get()
            # Delete each L2 domain
            for domain in domains:
                self.delete_vsd_domain(domain)
        except Exception, e:
            self.logger.error("VSD - while deleting l2domains")
            self.logger.error(repr(e))
            self.logger.info("syncing")
            return 1

    def delete_vsd_domain(self, domain):
        domain.maintenance_mode = "ENABLED"
        domain.save()
        vports = domain.vports.get()
        for vport in vports:
            self.logger.info("VSD - Deleting vport: {0}".format(vport.id))
            if vport.type == "BRIDGE":
                self.logger.info("VSD - Deleting bridgeport")
                try:
                    interface = vport.bridge_interfaces.get_first()
                    interface.delete()
                except Exception, e:
                    self.logger.info("VSD - no Bridgeinterface found")
                    self.logger.error(repr(e))
            if vport.type == "HOST":
                self.logger.info("VSD - Deleting hostport interface")
                try:
                    interface = vport.host_interfaces.get_first()
                    interface.delete()
                except Exception, e:
                    self.logger.info("VSD - no host interface found")
                    self.logger.error(repr(e))
            sleep(2)
            alarms = vport.alarms.get()
            for alarm in alarms:
                try:
                    alarm.delete()
                except Exception, e:
                    self.logger.info("VSD - while deleting alarm")
                    self.logger.error(repr(e))

            if vport.type != "CONTAINER":
                vport.delete()
            else:
                # delete container. This will delete the vport and its interface as well
                self.logger.info("VSD - Deleting Container")
                try:
                    interface = vport.containers.get_first()
                    interface.delete()
                except Exception:
                    self.logger.info("VSD - no Container found")
        domain.delete()

    def create_vsd_managed_tenant(self, tenant_name):
        self.logger.info("Creating VSD Managed Tenant: {0}".format(tenant_name))

        # Check if Nuage enterprise already exists
        enterprise = self.vsd_user.enterprises.get_first(filter='name==\"{0}\"'.format(tenant_name))
        if enterprise is not None:
            self.logger.info("Enterprise {0} already exist".format(tenant_name))

        # Check if project already exists
        try:
            project = self.keystone.projects.find(name="{0}".format(tenant_name))
        except keystone_NotFound:
            project = None
        else:
            self.logger.warn("OpenStack project {0} already exist ".format(tenant_name))

        if enterprise is not None or project is not None:
            var = raw_input("Either the Nuage enterprise or OpenStack project already exist. "
                            "Do you want to continue and use these Enterprise/project? (y/n)")
            if var != "y":
                return

        # Create project
        if project is None:
            self.logger.info("Creating Keystone Tenant: {0}".format(tenant_name))
            project = self.keystone.projects.create(name="{0}".format(tenant_name),
                                                    domain=self.cfg.get_value("openstack", "project_domain_id"),
                                                    description="VSD Managed Openstack Tenant",
                                                    enabled=True)
        # get admin role
        try:
            admin_role = self.keystone.roles.find(name='admin')
        except Exception as e:
            self.logger.error("Cannot find admin role in keystone")
            self.logger.error(repr(e))
            return

        # get admin user
        try:
            os_admin = self.keystone.users.find(name=self.cfg.get_value('openstack', 'admin_username'))
        except Exception as e:
            self.logger.error("Cannot find user {0} in keystone".
                              format(self.cfg.get_value('openstack', 'admin_username')))
            self.logger.error(repr(e))
            return

        # add admin role for admin user to project
        try:
            self.logger.info("Adding admin role for user {0} in tenant {1} in keystone".format(
                self.cfg.get_value('openstack', 'admin_username'), tenant_name))
            # will not throw an error if the role was already added
            self.keystone.roles.grant(role=admin_role, user=os_admin, project=project)
        except Exception as e:
            self.logger.error("Cannot add admin role for user {0} in tenant {1} in keystone".format(
                self.cfg.get_value('openstack', 'admin_username'), tenant_name))
            self.logger.error(repr(e))
            return

        # Create the netpartition
        # TODO: What if netpartition already exist in the neutron database, but the Enterprise does not exist
        try:
            self.logger.info("Creating Net-Partition: {0}".format(tenant_name))
            body_netpart = {
                "net_partition":
                    {
                        "name": tenant_name
                    }
            }
            self.neutron.create_net_partition(body=body_netpart)
        except neutron_NotFound:
            self.logger.info("Cannot create netpartition: {0}. Ignore this message if you are using the ML2 plugin. "
                             "Creating VSD enterprise....".format(tenant_name))
            # If this is the case, manually create the enterprise
            if enterprise is None:
                ent = vspk.NUEnterprise(name=tenant_name)
                self.vsd_user.create_child(ent)
        except Exception as e:
            self.logger.warn("Cannot create netpartition: {0}. ".format(tenant_name))
            self.logger.error(repr(e))
        self.logger.info("Finished Creating VSD Managed Tenant: {0}".format(tenant_name))

    def delete_vsd_managed_tenant(self, tenant_name, sync):
        self.logger.info("Deleting VSD Managed Tenant: {0}".format(tenant_name))
        var = raw_input("This will delete all existing VMs, subnets, the OpenStack project and Nuage Enterprise. "
                        "Type \"{0}\" if you are sure:".format(tenant_name))
        if var != tenant_name:
            self.logger.info("Aborting deleting VSD Managed Tenant: {0}".format(tenant_name))
            return

        # get Nuage enterprise
        enterprise = self.vsd_user.enterprises.get_first(filter='name==\"{0}\"'.format(tenant_name))
        if enterprise is None:
            self.logger.warn("Enterprise {0} not found".format(tenant_name))

        try:
            project = self.keystone.projects.find(name="{0}".format(tenant_name))
        except keystone_NotFound:
            project = None
            self.logger.warn("OpenStack project {0} not found".format(tenant_name))

        if enterprise is None or project is None:
            var = raw_input("Either the Nuage enterprise or OpenStack project does not exist. "
                            "Do you want to continue by deleting all remaining parts? (y/n)")
            if var != "y":
                return

        # Delete VMs in keystone project
        if project is not None:
            self.logger.info("Deleting all VMs for tenant: {0}".format(project.name))
            try:
                self.delete_vms_in_tenant(project)
            except Exception as e:
                self.logger.error("Cannot delete VMs from tenant {0}".format(project.name))
                self.logger.error(repr(e))
                return

        # Delete subnets in Nuage enterprise
        if enterprise is not None:
            self.logger.info("Deleting Nuage Enterprise: {0}".format(enterprise.name))
            try:
                self.delete_vsdobjects_in_tenant(enterprise)
            except Exception as e:
                self.logger.error("Cannot delete VSD Objects from enterprise {0}".format(enterprise.name))
                self.logger.error(repr(e))
                return

        # Delete subnets in openstack project
        if project is not None and enterprise is not None:
            try:
                # Remove existing subnets
                sync.sync_once_enterprise(enterprise, project)
            except Exception as e:
                self.logger.error("Cannot delete OpenStack subnets from project".format(project.name))
                self.logger.error(repr(e))
                return

        # Delete subnets in openstack project and delete project
        if project is not None:
            self.logger.info("Deleting Keystone project: {0}".format(project.name))
            try:
                project.delete()
            except Exception as e:
                self.logger.error("Cannot delete project {0} in keystone".format(project.name))
                self.logger.error(repr(e))
                return

        # Delete Nuage enterprise
        if enterprise is not None:
            try:
                enterprise.delete()
            except Exception as e:
                self.logger.error("Cannot delete VSD enterprise".format(tenant_name))
                self.logger.error(repr(e))
                return

        # Delete netpartition (Only for monolithic plugin)
        try:
            netpart_exists = self.netpartition_exists(tenant_name)
        except neutron_NotFound:
            self.logger.warn("Cannot find netpartition: {0}. Ignore this message if you are using the ML2 plugin"
                             .format(tenant_name))
        else:
            if not netpart_exists:
                self.logger.warn("Netpartition: {0} not found.".format(tenant_name))
                return
            else:
                try:
                    self.logger.info("Deleting Net-Partition: {0}".format(tenant_name))
                    netpart = self.neutron.list_net_partitions(name=tenant_name)['net_partitions'][0]
                    self.neutron.delete_net_partition(netpart['id'])
                except Exception as e:
                    self.logger.error("Cannot delete netpartition: {0}".format(tenant_name))
                    self.logger.error(repr(e))
        self.logger.info("Finished Deleting VSD Managed Tenant: {0}".format(tenant_name))

    def list_vsd_managed_tenants(self):
        """Retrieves a list of the managed tenants in VSD"""
        # TODO: Check if we can use nuage-netpartition-list instead. (Not supported with ML2 on Nuage 4.0)
        tenants = self.keystone.projects.list()

        table = PrettyTable(["ID", "name", "description"])
        for ksi in tenants:
            ent = self.vsd_user.enterprises.get_first(filter="name==\"{0}\"".format(ksi.name))
            if ent is not None:
                table.add_row([ent.id, ent.name, ent.description])
        print table
