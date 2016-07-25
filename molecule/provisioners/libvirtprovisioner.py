#  Copyright (c) 2015-2016 Cisco Systems
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#  THE SOFTWARE.

import collections
import os.path

try:
  from lxml import etree as ET
except ImportError:
    try:
        from xml.etree import cElementTree as ET
    except ImportError:
        from xml.etree import ElementTree as ET

import libvirt
import netaddr
import requests

from molecule import utilities
from molecule.provisioners import baseprovisioner


class LibvirtProvisioner(baseprovisioner.BaseProvisioner):
    def __init__(self, molecule):
        super(LibvirtProvisioner, self).__init__(molecule)
        self._provider = self._get_provider()
        self._platform = self._get_platform()
        self._libvirt = libvirt.open(self.molecule.config.config['libvirt']['uri'])
        self._pool_path = os.path.expanduser(os.path.join('~', '.libvirt', 'images'))
        self._sources_path = os.path.expanduser(os.path.join('~', '.libvirt', 'sources'))
        for p in [self._pool_path, self._sources_path]:
            if not os.path.exists(p):
                os.makedirs(p)

    def _get_provider(self):
        return 'libvirt'

    def _get_platform(self):
        return self.default_platform

    @property
    def name(self):
        return 'libvirt'

    @property
    def instances(self):
        return self.molecule.config.config['libvirt']['instances']

    @property
    def default_provider(self):
        return 'libvirt'

    @property
    def default_platform(self):
        return 'libvirt'

    @property
    def provider(self):
        return self._provider

    @property
    def platform(self):
        return self._platform

    @property
    def host_template(self):
        return '{} ansible_ssh_host={} ansible_ssh_user={} ansible_ssh_extra_args="-o ConnectionAttempts=5"\n'

    @property
    def valid_providers(self):
        return [{'name': 'Libvirt'}]

    @property
    def valid_platforms(self):
        return [{'name': 'Libvirt'}]

    @property
    def ssh_config_file(self):
        return None

    @property
    def testinfra_args(self):
        kwargs = {
            'ansible-inventory':
            self.m._config.config['ansible']['inventory_file'],
            'connection': 'ansible'
        }

        return kwargs

    @property
    def serverspec_args(self):
        return dict()

    @property
    def ansible_connection_params(self):
        params = {'connection': 'ssh'}

        return params

    def _create_pool(self, pool_name):
        """
        Define a libvirt storage pool and start it.

        :param: the name of the pool
        :param: the filesystem path for the pool
        """
        utilities.print_info("Creating libvirt storage pool for molecule ...")
        pool = ET.Element('pool', type='dir')
        ET.SubElement(pool, 'name').text = pool_name
        target = ET.SubElement(pool, 'target')
        ET.SubElement(target, 'path').text = self._pool_path
        poolxml = ET.tostring(pool)
        utilities.logger.debug("\tXMLDesc: {}".format(poolxml))
        newpool = self._libvirt.storagePoolDefineXML(poolxml)
        newpool.create()


    def _up_pool(self, pool_name='molecule'):
        pools = []
        # Ensure we have a storage pool to upload *to*
        for name in self._libvirt.listAllStoragePools():
            pool_found = False
            try:
                pool_found = self._libvirt.storagePoolLookupByName(pool_name)
            except libvirt.libvirtError:
                pass
            if pool_found:
                pools.append(pool_found)
                if not pool_found.isActive():
                    pool_found.create()
                return pools[0] # existing poolwork is now running
        if not len(pools) > 0:
            pools.append(self._create_pool(pool_name))
            return pools[0]


    def _create_network(self, network=None):
        """
        Define a libvirt network and start it.
        TODO: Make this all configurable. 'network' will be a dict that describes a libvirt network, populated based on molecule.yml.
        libvirt:
            networks:
                - name: molecule0
                  forward: nat|none
                  #bridge: virbr10
                  cidr: 192.168.121.1/24
        """
        cidr_net = netaddr.IPNetwork(network['cidr'])
        # Define/create a new network: 'molecule'
        utilities.print_info("Creating libvirt network for molecule ...")
        net = ET.Element('network', ipv6='yes')
        ET.SubElement(net, 'name').text = network['name']
        #forward = ET.SubElement(net, 'forward', type=network['forward'], dev=network['bridge'])
        if 'forward' in network:
            forward = ET.SubElement(net, 'forward', mode=getattr(network, 'forward', 'nat'))
            if network['forward'] == 'nat':
                nat = ET.SubElement(forward, 'nat')
                port = ET.SubElement(nat, 'port', start='1024', end='65535')
        #bridge = ET.SubElement(net, 'bridge', name=network['bridge'], stp='on', delay='0')
        ip = ET.SubElement(net, 'ip', address=str(cidr_net.ip), netmask=str(cidr_net.netmask))
        dhcp = ET.SubElement(ip, 'dhcp')
        dhcprange = ET.SubElement(dhcp, 'range', start=str(cidr_net.ip), end=str(list(cidr_net)[-1]))

        netxml = ET.tostring(net)
        utilities.logger.debug("\tXMLDesc: {}".format(netxml))
        newnet = self._libvirt.networkDefineXML(netxml)
        newnet.create()

    def _up_network(self, network=None):
        """
        Create/up a libvirt network.
        """
        # TODO: Remove this when we have molecule defaults for libvirt networks
        if not network:
            network = { 'name': 'molecule0', 'forward': 'nat', 'bridge': 'virbr10', 'cidr': '192.168.122.1/24' }

        nets = []
        for name in self._libvirt.listAllNetworks():
            net_found = False
            try:
                net_found = self._libvirt.networkLookupByName(network['name'])
            except libvirt.libvirtError:
                pass
            if net_found:
                nets.append(net_found)
                if not net_found.isActive():
                    net_found.create()
                return # existing network is now running
        if not len(nets) > 0:
            self._create_network(network)

    def _build_domain_xml(self, instance):
        """
        Builds a string of xml suitable for self._libvirt.defineXML(xml)

        :return: an xml string
        """
        utilities.print_info("\t{}: {}".format(instance['name'], instance))
        #required_elements = ['name', 'cpu', 'memory', 'os', 'features', 'devices']
        #for e in required_elements:
            #pass

        # Basic elements
        dom = ET.Element('domain', type='kvm')
        ET.SubElement(dom, 'name').text = instance['name']
        cpu = ET.SubElement(dom, 'cpu')
        topology = ET.SubElement(cpu, 'topology', sockets=str(instance['cpu']['sockets']), cores=str(instance['cpu']['cores']), threads=str(instance['cpu']['threads']))
        ET.SubElement(dom, 'memory', unit='MiB').text = str(instance['memory'])
        os_element = ET.SubElement(dom, 'os')
        ET.SubElement(os_element, 'type').text = 'hvm'
        boot = ET.SubElement(os_element, 'boot', dev='hd')
        ET.SubElement(dom, 'on_crash').text = 'restart'
        features = ET.SubElement(dom, 'features')
        for f in ['acpi', 'apic', 'pae']:
            features.append(ET.Element(f))
        devices = ET.SubElement(dom, 'devices')

        # Disk elements
        disk = ET.SubElement(devices, 'disk', type='file', device='disk')
        ET.SubElement(disk, 'driver', name='qemu', type='qcow2')
        ET.SubElement(disk, 'source', file=(os.path.join(self._pool_path, instance['name'] + '.img')))
        backing = ET.SubElement(disk, 'backingStore', type='file')
        ET.SubElement(backing, 'format', type='qcow2')
        ET.SubElement(backing, 'source', file=os.path.join(self._sources_path, instance['image']['name'] + '.img'))
        ET.SubElement(backing, 'backingStore')
        ET.SubElement(disk, 'target', dev='vda', bus='virtio')
        # Do we need alias/address elements here?

        # Serial/console/usb elements
        serial = ET.SubElement(devices, 'serial', type='pty')
        target = ET.SubElement(serial, 'target', port='0')
        alias = ET.SubElement(serial, 'alias', name='serial0')


        console = ET.SubElement(devices, 'console', type='pty')
        target = ET.SubElement(console, 'target', port='0', type='serial')
        alias = ET.SubElement(console, 'alias', name='serial0')

        # Network interface elements
        #iface = ET.SubElement(devices, 'interface', type='network')
        #ET.SubElement(iface, 'source', network='default')
        for nic in instance['interfaces']:
            iface = ET.SubElement(devices, 'interface', type='network') 
            ET.SubElement(iface, 'source', network=nic['network_name'])
            #ET.SubElement(iface, 'target', dev='vnet' + str(instance['interfaces'].index(nic)))
            ET.SubElement(iface, 'model', type='e1000')
        # Finally
        domxml = ET.tostring(dom)
        utilities.print_info("\tXMLDesc: {}".format(domxml))
        return domxml

    def _fetch_image(self, url, filename):
        utilities.print_info("Fetching image {} ...".format(url))
        r = requests.get(url, stream=True)
        with open(os.path.join(self._sources_path, filename), 'wb') as fd:
            for chunk in r.iter_content(chunk_size=4096):
                    fd.write(chunk)


    def _create_volume(self, pool, instance):
        utilities.print_info("Creating libvirt volume for instance {}".format(instance['name']))
        vol = ET.Element('volume', type='file')
        ET.SubElement(vol, 'name').text = instance['name'] + '.img'
        ET.SubElement(vol, 'capacity', unit='GiB').text = '40'
        target = ET.SubElement(vol, 'target')
        ET.SubElement(target, 'path').text = os.path.join(self._pool_path, instance['name'] + '.img')
        ET.SubElement(target, 'format', type='qcow2')
        volxml = ET.tostring(vol)
        utilities.logger.debug("\tXMLDesc: {}".format(volxml))
        newvol = pool.createXML(volxml)
        utilities.print_success("\tCreated volume for {}.\n".format(instance['name']))

    def _destroy_volume(self, pool, instance):
        utilities.print_info("\t\tDestroying libvirt volume for instance {}".format(instance['name']))
        try:
            vol = pool.storageVolLookupByName(instance['name'] + '.img')
            vol.delete()
        except libvirt.libvirtError:
            utilities.logger.warning("\t\tNo volume for {}".format(instance['name']))
            return
        utilities.print_success('\t\tDestroyed libvirt volume for {}'.format(instance['name']))

    def up(self, no_provision=True):
        for net in self.molecule.config.config['libvirt']['networks']:
            self._up_network(net)
        pool = self._up_pool()
        vols = pool.listAllVolumes()
        domains = self._libvirt.listAllDomains()
        for instance in self.instances:
            # Ensure that the image source is available
            if not os.path.exists(os.path.join(self._sources_path, instance['image']['name'] + '.img')):
                self._fetch_image(instance['image']['source'], instance['image']['name'] + '.img')
            # Is there an existing libvirt volume for this instance? If not, create one
            vol_found = False
            for vol in vols:
                if vol.name() == instance['name'] + '.img':
                    vol_found = True
                    break
            if not vol_found:
                self._create_volume(pool, instance)
            # Is there an existing libvirt domain defined for this instance?
            dom_found = False
            for dom in domains:
                if not dom_found:
                    if dom.name() == instance['name']:
                        dom_found = True
                        if dom.info()[0] == 1:
                            utilities.print_info("\t{}: already running".format(instance['name']))
                            break
                        else:
                            utilities.print_info("\t{}: booting".format(instance['name']))
                            dom.create() 
                            utilities.print_success("\tUpped instance {}.\n".format(instance['name']))
            if not dom_found:
                utilities.print_info("\t{}: defining".format(instance['name']))
                dom = self._libvirt.defineXML(self._build_domain_xml(instance))
                utilities.print_success("\tCreated instance {}.\n".format(instance['name']))
                utilities.print_info("\t{}: booting".format(instance['name']))
                try:
                    dom.create()
                except libvirt.libvirtError as e:
                    utilities.logger.error("\nFailed to create/boot {}: {}".format(instance['name'], e))
                    dom.undefine()

    def destroy(self):
        domains = self._libvirt.listAllDomains()
        pool = self._up_pool()
        for instance in self.instances:
            utilities.print_info("\tDestroying libvirt instance {} ...".format(instance['name']))
            dom_found = False
            for dom in domains:
                if not dom_found:
                    if dom.name() == instance['name']:
                        dom.destroy()
                        dom.undefine()
                        utilities.print_success('\tDestroyed and undefined libvirt instance {}'.format(instance['name']))
            # Destroy volume
            self._destroy_volume(pool, instance)
            # TODO: Consider whether to destroy/undefine molecule networks if they are no longer used

    def status(self):
        states = ['no state', 'running', 'blocked', 'paused', 'being shutdown', 'shutoff', 'crashed', 'pmsuspended']
        Status = collections.namedtuple('Status', ['name', 'state', 'provider'])
        status_list = []
        ins_found = False
        domains = self._libvirt.listAllDomains()
        for instance in self.instances:
            for dom in domains:
                if not ins_found:
                        if dom.name() == instance['name']:
                            ins_found = True
                            status_list.append(Status(name=instance['name'],state=states[dom.info()[0]], provider='Libvirt'))
            if not ins_found:
                status_list.append(Status(name=instance['name'],state='undefined', provider='Libvirt'))

        return status_list


    def _ips(self, interfaces):
        """
        Get IP addresses, appending the IP address to each tuple.
        
        :param: a list of tuples: (MAC address, (libvirt) name of network)
        :return: a list of tuples: (MAC address, (libvirt) name of network, IP address)
        """
        for interface in interfaces:
            net = self._libvirt.networkLookupByName(interface[1])
            leases = net.DHCPLeases()
            if not leases:
                return None
            for lease in leases:
                print(lease)
                if lease['mac'] == mac:
                    utilities.print_info("\t\tIPs for mac {}: {}".format(mac, lease['ipaddr']))
                    interface.append(lease['ipaddr'])
                    print(interface)

        return interfaces

    def _macs(self, domain):
        """
        Get the list of MAC addresses for a running domain.

        :param: a libvirt domain object
        :return: a list of tuples: (MAC address, (libvirt) name of network)
        """
        interfaces = []
        dom = ET.fromstring(domain.XMLDesc())
        nics = [e for e in dom.findall('./devices/interface[mac]')]
        for nic in nics:
            mac = nic.find('./mac[@address]').get("address")
            source_net = nic.find('./source[@network]').get("network")
            interfaces.append((mac, source_net))
        return interfaces

    def inventory_entry(self, instance):
        template = self.host_template

        domains = self._libvirt.listAllDomains()
        if len(domains) == 0:
            return ''
        for dom in domains:
            if dom.name() == instance['name']:
                macs = self._macs(dom)
                ips = self._ips(macs)
                if ips and len(ips[0]) > 2:
                    # TODO: un-hardcode this test, so that we're not assuming which network molecule should use for the Ansible connection
                    ips = [ip for ip in ips if ip[1] == 'molecule0']
                    return template.format(instance['name'],
                                       ips[0][2],
                                       instance['sshuser'])
                else:
                    return template.format(instance['name'],
                                       None,
                                       instance['sshuser'])
        return ''

    def conf(self, name=None):

        with open(self.molecule.config.config['molecule'][
                'inventory_file']) as instance:
            for line in instance:
                if line.split()[0] == name:
                    ansible_host = line.split()[1]
                    host_address = ansible_host.split('=')[1]
                    return host_address
        return None

    def login_cmd(self, instance_name):
        return 'ssh {} -l {}'

    def login_args(self, instance_name):

        # Try to retrieve the SSH configuration of the host.
        conf = self.conf(name=instance_name)
        user = ''

        for instance in self.instances:
            if instance_name == instance['name']:
                user = instance['sshuser']

        return [conf, user]
