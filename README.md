# nuage-neutron-sync

The goal of `nuage-neutron-sync` is to provide an automatic synchronization between Nuage Networks domain topologies and OpenStack tenant networks. As such, an end-user can easily provision new virtual machines in networks that have been created by the network admin.

Internally it monitors the creation and removal of subnets in Nuage enterprises and ensures the coresponding networks and subnets are mapped in OpenStack. It covers subnets of L3 domains and DHCP-Managed L2 domains. It does not support Shared Subnets, FloatingIP Subnets, or other types of L2 domains.

As an example, suppose a network administrator of the *ACME* enterprise has created the following topology in VSD Architect:
![Nuage-Enterprise-Topology][nuage-subnet-list]

These subnets will be made available to the *ACME* tenant in OpenStack like this:
![OpenStack-Network-List][os-subnet-list]

# Usage

The `nuage-neutron-sync` synchronizes networks between a Nuage Networks Enterprise and an OpenStack Tenant.
For the example of Nuage Networks Enterprise `ACME`, it expects following OpenStack commands to be issued first:

```
# keystone tenant-create --name ACME
# keystone user-role-add --user admin --tenant ACME --role admin
# neutron nuage-netpartition-create ACME
```

This is sufficient for `nuage-neutron-sync`  to start populating the ACME tenant with all networks as they are provisioned under the Nuage Networks ACME enterprise. It will use the admin user as configured in the `nuage-neutron-sync.conf` file.


# Install Instructions

The below instructions will install the nuage-neutron-sync tool on a RHEL or CentOS machine.

## Assumptions

- Nuage VSP is installed and configured in the network,
- The following OpenStack services are installed and configured,
 - Identity (Keystone),
 - Networking (Neutron),
 - Compute (Nova).
 - Nuage Neutron Plugin is installed and configured on the neutron server.

## Tested OpenStack Distributions


- Mitaka 
 - OSP 9.0

## Required Software Packages

The following software must be available on the linux server/VM, please make sure the Keystone client, Neutron client, Nova client and Nuage packages are of the same version as your environment:

- Python interpreter 2.7,
- python-docopt,
- MySQL-python,
- OpenStack: python-keystoneclient,
- OpenStack: python-neutronclient,
- OpenStack: python-novaclient,
- Nuage: vspk Python,
- Nuage: neutronclient plugin,


## nuage-neutron-sync user
A nuage-neutron-sync user needs to be created on the VSD.

Step 1: Log in on the VSD UI as csproot/csp.

Step 2: Go to "Platform Configuration" > "Users" and create a user named "nuage-neutron-sync".

Step 3: Go to "Groups" and assign this user to the Root Group.

Step 4: SSH to the VSD VM and generate certificates for the nuage-neutron-sync user.

```
/opt/vsd/ejbca/deploy/certMgmt.sh -a generate -u nuage-neutron-sync -c nuage-neutron-sync -o csp -f pem -t client
```
The generated certificates are stored in /opt/vsd/ejbca/p12/pem/

## Installation Steps for a CentOS / RedHat server

The procedure below explains the first time installation. Follow the steps in the Upgrade section when an older version of `nuage-neutron-sync` is already deployed.

Step 1: Login as a root to a server or a VM, and navigate to the directory where nuage-neutron-sync is to be installed

Step 2: Clone the `nuage-neutron-sync` software from github, and run the `setup.py install` script

```
# git clone https://github.com/nuagenetworks/nuage-neutron-sync.git
# cd nuage-neutron-sync
# python setup.py install
```

# Configuration

Step 1: Open the configuration file `/etc/nuage-neutron-sync/nuage-neutron-sync.conf` with a text editor.

```
# vi /etc/nuage-neutron-sync/nuage-neutron-sync.conf
```

Step 2: Configure logging.

```
[logging]
loglevel = INFO
rotate_logfiles = True
maxsize = <maximum size of one logfile in Mega bytes>
backups = <maximum number of logfiles>
```

Step 3: Set the VSD server and configure the nuage-neutron-sync user. Copy over the certificate and key from the VSD and store them in /etc/nuage-neutron-sync. Port 7443 of the VSD is used for certificate based log in.

```
[vsd]
api_url = https://<vsd host ip>:7443
username = nuage-neutron-sync
enterprise = csp
cert=/etc/nuage-neutron-sync/nuage-neutron-sync.pem
key=/etc/nuage-neutron-sync/nuage-neutron-sync-Key.pem
version = v4_0
```

Step 5: set the OpenStack credentials.

Use admin user and tenant, the admin user must have `admin` role for all projects to synchronize,


```
[openstack]
admin_username = admin
admin_password = <admin password>
admin_tenant = admin
project_domain_id = Default
user_domain_id = Default
auth_url = http:// <keystone host ip>:5000/v3

[db_neutron]
db_hostname = <neutron mysql host ip>
db_username = <neutron mysql username>
db_password = <neutron mysql password>
db_name = <neutron DB name>
```

Step 6: Configure the format for subnet names under OpenStack
You can also specify a comma-separated list of tenants that should not be included for synchronizion. Typically you would include the name of the default Nuage enterprise used for OpenStack-Managed networking.

```
[sync]
l2_name_format = $d
l3_name_format = $d ($z) \ $s
excluded_enterprises = OpenStack_Org
sync_shared_subnets = False
interval = 10
```

By default, nuage-neutron-sync will not synchronize Nuage (L2/L3) Shared Subnets. This can be enabled by setting sync_shared_subnets to True in which case a Nuage shared subnet will be mapped into every tenant. It's up to the end-user to avoid any IP conflicts. For example, if two tenants both use the same shared subnet and both create a VM in it, OpenStack could potentially pick the same IP address (not knowing they belong to the same Nuage subnet). To avoid conflicts, create a port with the fixed-ip option and attach it to the VM during creation.

```
neutron port-create <NETWORK> --fixed-ip ip_address=<IP_ADDR>
```

Another way of preventing IP conflicts in shared subnets is the use of allocation pools. Because the number and size of the pools differs for each use case, this functionality has not been built in. 

Note that Floating IP subnets will **not** be mapped.

Step 7: Enable and start `nuage-neutron-syncd` through `systemctl`.

```
# systemctl daemon-reload
# systemctl start nuage-neutron-syncd
# systemctl enable nuage-neutron-syncd
# systemctl status nuage-neutron-syncd.service
Active: active (running)
```

[nuage-subnet-list]: sample/Nuage-subnet-list.PNG
[os-subnet-list]: sample/OS-subnet-list.PNG



