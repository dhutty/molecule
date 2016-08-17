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
import getpass
import os.path
import shlex
import subprocess
import tarfile
import time

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

LOG = utilities.get_logger(__name__)


class LibvirtProvisioner(baseprovisioner.BaseProvisioner):
    """
    Implements a Molecule provisioner that uses libvirt to provision instances.
    """

    def __init__(self, molecule):
        super(LibvirtProvisioner, self).__init__(molecule)
        self._provider = self._get_provider()
        self._platform = self._get_platform()
        self._libvirt = libvirt.open(self.molecule.config.config['libvirt'][
            'uri'])
        self._pool_path = os.path.expanduser(
            os.path.join('/opt/jenkins', 'libvirt', 'images'))
        self._sources_path = os.path.expanduser(
            os.path.join('/opt/jenkins', 'libvirt', 'sources'))
        for path in [self._pool_path, self._sources_path]:
            if not os.path.exists(path):
                os.makedirs(path, 0775)

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
        return ''

    @property
    def provider(self):
        return self._provider

    @property
    def platform(self):
        return self._platform

    @property
    def host_template(self):
        return '{} ansible_ssh_host={} ansible_ssh_private_key_file={} ansible_ssh_user={}\n'

    @property
    def valid_providers(self):
        return [{'name': 'Libvirt'}]

    @property
    def valid_platforms(self):
        return [{'name': 'Libvirt'}]

    @property
    def ssh_config_file(self):
        return '.molecule/ssh_config'

    @property
    def testinfra_args(self):
        kwargs = {
            'ansible-inventory':
            self.molecule.config.config['ansible']['inventory_file'],
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

    def _define_pool(self, pool_name):
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
        LOG.debug("\tXMLDesc: {}".format(poolxml))
        newpool = self._libvirt.storagePoolDefineXML(poolxml)
        newpool.create()
        return newpool

    def _up_pool(self, pool_name='molecule'):
        """
        Up or define/up a libvirt storage pool

        :param: name for the pool
        """
        try:
            pool_found = self._libvirt.storagePoolLookupByName(pool_name)
            if pool_found and not pool_found.isActive():
                pool_found.create()
            return pool_found  # existing pool is now running
        except libvirt.libvirtError:
            return self._define_pool(pool_name)

    def _define_network(self, network=None):
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
        utilities.print_info("Creating libvirt network: {}".format(network[
            'name']))
        net = ET.Element('network', ipv6='no')
        ET.SubElement(net, 'name').text = network['name']
        if 'forward' in network and network['forward'] != 'none':
            forward = ET.SubElement(net, 'forward', mode='nat')
            nat = ET.SubElement(forward, 'nat')
            port = ET.SubElement(nat, 'port', start='1024', end='65535')
        if 'bridge' in network:
            bridge = ET.SubElement(
                net, 'bridge', name=network['bridge'], stp='on', delay='0')
        ip = ET.SubElement(
            net, 'ip', address=str(cidr_net.ip), netmask=str(cidr_net.netmask))
        want_dhcp = network.get('dhcp', True)
        if want_dhcp:
            dhcp = ET.SubElement(ip, 'dhcp')
            dhcprange = ET.SubElement(
                dhcp,
                'range',
                start=str(cidr_net.ip),
                end=str(list(cidr_net)[-2]))

        netxml = ET.tostring(net)
        LOG.debug("\tXMLDesc: {}".format(netxml))
        newnet = self._libvirt.networkDefineXML(netxml)
        return newnet.create()

    def _up_network(self, network=None):
        """
        Up or define/up a libvirt network.

        :param: a dict describing the network, with unique 'name' and 'cidr' keys
        """
        # TODO: Remove this when we have molecule defaults for libvirt networks
        if not network:
            network = {'name': 'molecule0',
                       'forward': 'nat',
                       'bridge': 'virbr10',
                       'cidr': '192.168.122.1/24'}

        try:
            net_found = self._libvirt.networkLookupByName(network['name'])
            if net_found and not net_found.isActive():
                net_found.create()
            return net_found  # existing network is now running
        except libvirt.libvirtError:
            return self._define_network(network)

    def _build_domain_xml(self, instance):
        """
        Builds a string of xml suitable for self._libvirt.defineXML(xml)

        :param: a dict that describes an instance (a virtualization guest that this provisioner should create)
        :return: an xml string
        """

        # Basic elements
        dom = ET.Element('domain', type='kvm')
        ET.SubElement(dom, 'name').text = instance['name']
        cpu = ET.SubElement(dom, 'cpu', mode='host-model')
        model = ET.SubElement(cpu, 'model', fallback='allow')
        if 'cpu' in instance:
            topology = ET.SubElement(
                cpu,
                'topology',
                sockets=str(instance['cpu']['sockets']),
                cores=str(instance['cpu']['cores']),
                threads=str(instance['cpu']['threads']))
        ET.SubElement(
            dom, 'memory', unit='MiB').text = str(instance.get('memory', 1024))
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
        ET.SubElement(
            disk, 'driver', name='qemu', type='qcow2', cache='default')
        ET.SubElement(
            disk,
            'source',
            file=(os.path.join(self._pool_path, instance['name'] + '.img')))
        ET.SubElement(disk, 'target', dev='vda', bus='virtio')

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
        for nic in instance.get('interfaces', [{'network_name': 'default'}]):
            iface = ET.SubElement(devices, 'interface', type='network')
            ET.SubElement(iface, 'source', network=nic['network_name'])
            ET.SubElement(iface, 'model', type='virtio')
        # Finally
        domxml = ET.tostring(dom)
        LOG.debug("\tXMLDesc: {}".format(domxml))
        return domxml

    def _fetch(self, url, filename):
        """
        Fetches a URL, saves response to <filename>.

        :param: URL to fetch
        :param: destination filename, will be in either self._sources_path or self._pool_path
        """
        if filename.endswith('.box'):
            path = self._sources_path
        else:
            path = self._pool_path
        utilities.print_info("Fetching image {} \n\t to {}...".format(
            url, os.path.join(path, filename)))
        r = requests.get(url, stream=True)
        if r.status_code != 200:
            try:
                os.unlink(os.path.join(path, filename))
            except OSError:
                pass
            r.raise_for_status()
        with open(os.path.join(path, filename), 'wb') as fd:
            for chunk in r.iter_content(chunk_size=4096):
                fd.write(chunk)

    def _unpack_box(self, image, imagefile):
        """
        Extract the qcow2 image file from a Vagrant box into a libvirt storage pool so it can be used as a backing store.

        :param: a dict of the 'name' and 'source' URL for the image
        :param: path to the box file
        """
        # A vagrant box is actually just a .tar.gz from which we need to extract the .img
        boxfile = os.path.join(self._sources_path, imagefile)
        utilities.print_info("Unpacking boxfile {} ...".format(boxfile))
        targz = tarfile.open(boxfile, mode='r:gz')
        members = targz.getmembers()
        for member in members:
            if member.name.endswith('.img'):
                targz.extract(member, self._pool_path)
                os.rename(
                    os.path.join(self._pool_path, member.name),
                    os.path.join(self._pool_path, image['name'] + '.img'))

    def _create_volume(self, pool, instance):
        """
        Create a libvirt storage volume for an instance

        :param: Libvirt Storage Pool object
        :param: a dict that describes an instance
        """
        utilities.print_info("Creating libvirt volume for instance {}".format(
            instance['name']))
        vol = ET.Element('volume', type='file')
        ET.SubElement(vol, 'name').text = instance['name'] + '.img'
        ET.SubElement(vol, 'capacity', unit='GiB').text = '40'
        target = ET.SubElement(vol, 'target')
        ET.SubElement(target, 'format', type='qcow2')
        backing = ET.SubElement(vol, 'backingStore')
        ET.SubElement(backing, 'path').text = os.path.join(
            self._pool_path, instance['image']['name'] + '.img')
        ET.SubElement(backing, 'format', type='qcow2')
        volxml = ET.tostring(vol)
        LOG.debug("\tXMLDesc: {}".format(volxml))
        newvol = pool.createXML(volxml)
        utilities.print_success("\tCreated volume for {}.\n".format(instance[
            'name']))

    def _destroy_volume(self, pool, instance):
        """
        Destroy a libvirt storage volume for an instance

        :param: Libvirt Storage Pool object
        :param: a dict that describes an instance
        """
        utilities.print_info(
            "\t\tDestroying libvirt volume for instance {}".format(instance[
                'name']))
        try:
            vol = pool.storageVolLookupByName(instance['name'] + '.img')
            vol.delete()
        except libvirt.libvirtError:
            LOG.warning("\t\tNo volume for {}".format(instance['name']))
            return
        utilities.print_success('\t\tDestroyed libvirt volume for {}'.format(
            instance['name']))

    def _populate_image(self, instance):
        image = instance.get(
            'image', self.molecule.config.config['libvirt']['images'][0])
        for k in ['source', 'ssh_user', 'ssh_key']:
            image[k] = image.get(k, filter(
                lambda imgname: imgname['name'] == image['name'],
                self.molecule.config.config['libvirt']['images'])[0][k])
        for index, inst in enumerate(self.molecule.config.config['libvirt'][
                'instances']):
            if inst['name'] == instance['name']:
                if 'image' in self.molecule.config.config['libvirt'][
                        'instances'][index]:
                    self.molecule.config.config['libvirt']['instances'][index][
                        'image'].update(image)
                else:
                    self.molecule.config.config['libvirt']['instances'][index][
                        'image'] = image
        return image

    def up(self, no_provision=True):
        """
        Up or define/up a libvirt instance.

        :param: no_provision is not meaningful for libvirt instances
        """
        for net in self.molecule.config.config['libvirt']['networks']:
            self._up_network(net)
        pool = self._up_pool()
        vols = pool.listAllVolumes()
        domains = self._libvirt.listAllDomains()
        for instance in self.instances:
            # Get image config
            image = self._populate_image(instance)
            imagefile = image['source'].split('/')[-1]
            # Ensure that the image is available
            if not os.path.exists(
                    os.path.join(self._pool_path, image['name'] + '.img')):
                if not os.path.exists(
                        os.path.join(self._sources_path, imagefile)):
                    self._fetch(image['source'], imagefile)
                if imagefile.endswith('.box'):
                    self._unpack_box(image, imagefile)

            # Is there an existing libvirt volume for this instance?
            try:
                vol_found = pool.storageVolLookupByName(instance['name'])
                if vol_found and not vol_found.isActive():
                    vol_found.create()
                return vol_found  # existing volume is now running
            except libvirt.libvirtError as e:
                self._create_volume(pool, instance)
            # TODO: Are all this instance's interface's networks available?
            # Is there an existing libvirt domain defined for this instance?
            dom_found = False
            for dom in domains:
                if not dom_found:
                    if dom.name() == instance['name']:
                        dom_found = True
                        if dom.info()[0] == 1:
                            utilities.print_info(
                                "\t{}: already running".format(instance[
                                    'name']))
                            break
                        else:
                            utilities.print_info("\t{}: booting".format(
                                instance['name']))
                            dom.create()
                            time.sleep(15)
            if not dom_found:
                utilities.print_info("\t{}: defining".format(instance['name']))
                dom = self._libvirt.defineXML(self._build_domain_xml(instance))
                utilities.print_success("\tCreated instance {}.\n".format(
                    instance['name']))
                utilities.print_info("\t{}: booting".format(instance['name']))
                try:
                    dom.create()
                    time.sleep(15)
                except libvirt.libvirtError as e:
                    LOG.error("\nFailed to create/boot {}: {}".format(instance[
                        'name'], e))
                    dom.undefine()

    def destroy(self):
        """
        Destroy/undefine a libvirt instance.

        Since molecule-created instances are ephemeral, always undefine the libvirt domain and its storage volume.
        """
        domains = self._libvirt.listAllDomains()
        pool = self._up_pool()
        for instance in self.instances:
            utilities.print_info("\tDestroying libvirt instance {} ...".format(
                instance['name']))
            dom_found = False
            for dom in domains:
                if not dom_found:
                    if dom.name() == instance['name']:
                        dom_found = True
                        dom.destroy()
                        dom.undefine()
                        utilities.print_success(
                            '\tDestroyed and undefined libvirt instance {}'.format(
                                instance['name']))
            # Destroy volume
            try:
                self._destroy_volume(pool, instance)
            except:
                # TODO: Consider whether this really cause molecule to exit fail?
                pass
            # TODO: Consider whether to destroy/undefine molecule networks if they are no longer used
        return True

    def status(self):
        states = ['no state', 'running', 'blocked', 'paused', 'being shutdown',
                  'shutoff', 'crashed', 'pmsuspended']
        Status = collections.namedtuple('Status',
                                        ['name', 'state', 'provider'])
        status_list = []
        domains = self._libvirt.listAllDomains()
        for instance in self.instances:
            ins_found = False
            for dom in domains:
                if not ins_found:
                    if dom.name() == instance['name']:
                        ins_found = True
                        status_list.append(
                            Status(
                                name=instance['name'],
                                state=states[dom.info()[0]],
                                provider='Libvirt'))
            if not ins_found:
                status_list.append(
                    Status(
                        name=instance['name'],
                        state='undefined',
                        provider='Libvirt'))

        return status_list

    def _lease_ip(self, interface):
        """
        Lease IP address

        :param: an interface dict that has at least: {'mac': MAC address, 'network_name': (libvirt) name of network}
        :return: an IP address
        """
        delay = 1
        max_count = 8
        net = self._libvirt.networkLookupByName(interface['network_name'])
        count = 0
        while not 'ip' not in interface:
            count = count + 1
            if count > max_count:
                return None
            utilities.print_info(
                "\t\t Waiting for DHCP for network: {}".format(interface[
                    'network_name']))
            time.sleep(delay + count)
            leases = net.DHCPLeases()
            if not leases:
                time.sleep(delay + count)
                continue
            for lease in leases:
                if lease['mac'] == interface['mac']:
                    utilities.print_success(
                        "\t\tIP leased for mac {} on network: {}: {}".format(
                            interface['mac'], interface['network_name'], lease[
                                'ipaddr']))
                    interface['ip'] = lease['ipaddr']
                    return interface['ip']

    def _nics(self, domain):
        """
        Retrieve a list of network interfaces

        :param: a libvirt domain object
        :return: list of interfaces
        """
        dom = ET.fromstring(domain.XMLDesc())
        nics = [e for e in dom.findall('./devices/interface[mac]')]
        return nics

    def _get_ip(self, mac):
        """
        Search libvirt's networks' leases for this MAC, return its IP address

        :param: a MAC address, formatted as in libvirt's XML: 'AA:BB:CC:DD:EE:FF'
        :return: an IPv4 address
        """
        nets = self._libvirt.listAllNetworks()
        for net in nets:
            leases = net.DHCPLeases()
            for lease in leases:
                if lease['mac'] == mac:
                    return lease['ipaddr']
        return None

    def _macs(self, domain, network):
        """
        Get the list of MAC addresses for a running domain.

        :param: a libvirt domain object
        :param: the name of the network
        :return: a list of MAC addresses that this domain has on the specified network
        """
        macs = []
        nics = self._nics(domain)
        for nic in nics:
            mac = nic.find('./mac[@address]').get("address")
            source_net = nic.find('./source[@network]').get("network")
            if source_net == network:
                macs.append(mac)
        return macs

    def inventory_entry(self, instance):
        template = self.host_template
        # TODO: replace with using "proper" defaults
        instance['interfaces'] = instance.get('interfaces',
                                              [{'network_name': 'default'}])
        domains = self._libvirt.listAllDomains()
        image = self._populate_image(instance)
        if len(domains) == 0:
            return ''
        time.sleep(10)
        for dom in domains:
            if dom.name() == instance['name']:
                utilities.print_info("\tDHCP for instance: {}".format(instance[
                    'name']))
                # In case no interfaces get an IP address. Perhaps this should be a fatal error, since molecule cannot run Ansible?
                entry = template.format(instance['name'], None,
                                        os.path.expanduser(image['ssh_key']),
                                        image['ssh_user'])
                for index, iface in enumerate(instance['interfaces']):
                    instance['interfaces'][index]['mac'] = self._macs(dom, iface['network_name'])[
                        0]  # Assumes a single MAC for this instance on this network: probably valid
                    instance['interfaces'][index]['ip'] = self._get_ip(iface['mac'])
                    if instance['interfaces'][index]['ip']:
                        utilities.print_success(
                            "\t\tIP found for mac {} on network: {}: {}".format(
                                iface['mac'], iface['network_name'], iface[
                                    'ip']))
                        entry = template.format(instance['name'], instance['interfaces'][index]['ip'],
                                                image['ssh_key'],
                                                image['ssh_user'])
                        # TODO: This means the network named 'default' is special and must be present
                        if iface['network_name'] == 'default':
                            instance['ip'] = instance['interfaces'][index]['ip']
                        break
                    instance['interfaces'][index]['ip'] = self._lease_ip(iface)
                    if instance['interfaces'][index]['ip']:
                        # TODO: This means the network named 'default' is special and must be present
                        if iface['network_name'] == 'default':
                            entry = template.format(
                                instance['name'], instance['interfaces'][index]['ip'],
                                os.path.expanduser(image['ssh_key']),
                                image['ssh_user'])
                            instance['ip'] = instance['interfaces'][index]['ip']
                            break
                # By this point, we should have waited for each NIC to dhcp, any that don't have IPs should be dhcliented
                for index, iface in enumerate(instance['interfaces']):
                    if 'ip' not in iface:
                        cmd = []
                        login_args = [
                            instance['image']['ssh_user'],
                            os.path.expanduser(instance['image']['ssh_key']),
                            instance['ip']
                        ]
                        login_cmd = 'ssh {} -i {} -l {} {}'
                        cmd.extend(
                            shlex.split(
                                login_cmd.format(
                                    instance['ip'], os.path.expanduser(
                                        instance['image']['ssh_key']),
                                    instance['image']['ssh_user'],
                                    '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null')))
                        device = ''.join(['eth', str(index)])
                        # Check for redhat-derivative && NetworkManager? => use nmcli
                        rh_derivative = False
                        try:
                            rh_check_cmd = cmd + ['pgrep', '-a',
                                                  'NetworkManager']
                            rh_derivative = subprocess.check_output(
                                rh_check_cmd)
                        except subprocess.CalledProcessError, e:
                            pass

                        if rh_derivative:
                            cmd.append(' '.join(
                                ['pgrep', '-a', 'dhclient', '|', 'grep',
                                 device, '||', 'sudo', '/usr/bin/nmcli', 'con',
                                 'add', 'type', 'ethernet', 'con-name',
                                 'molecule-' + device, 'ifname', device]))
                        else:
                            # Not redhat-derivative or no NetworkManager? => run dhclient.
                            # This should take care of *at least* debian-derivatives, likely other linux distros and some other *nix
                            cmd.append(' '.join(
                                ['pgrep', '-a', 'dhclient', '|', 'grep',
                                 device, '||', 'sudo', 'dhclient', device]))
                        utilities.print_info(
                            "\tRunning dhclient for interface {} on instance: {}".format(
                                iface['network_name'], instance['name']))
                        try:
                            res = subprocess.check_output(
                                cmd, stderr=subprocess.STDOUT)
                        except subprocess.CalledProcessError, e:
                            pass
                # Update self.molecule.config.config['libvirt']['instances'] with HostName from 'default' interface
                if 'ip' in instance:
                    instance['HostName'] = instance['ip']
                else:
                    instance['HostName'] = self._lease_ip(
                        {'network_name': 'default',
                         'mac': self._macs(dom, 'default')})
                for index, inst in enumerate(self.molecule.config.config[
                        'libvirt']['instances']):
                    if inst['name'] == instance['name']:
                        self.molecule.config.config['libvirt']['instances'][
                            index].update(instance)
                instance['User'] = instance['image']['ssh_user']
                instance['IdentityFile'] = os.path.expanduser(instance[
                    'image']['ssh_key'])
                # Write a ssh-config based on state
                kwargs = {'instances': self.instances}
                LOG.debug("\tWriting ssh_config using: {}".format(kwargs))
                utilities.write_template(
                    self.molecule.config.config['molecule'][
                        'ssh_config_template'], '.molecule/ssh_config',
                    kwargs=kwargs)
        return entry

    def conf(self, name=None, ssh_config=None):
        """
        Parse the inventory file, return a hash for login_args()
        """
        if ssh_config:
            # read the state file as yaml
            return None
        else:
            conf = {}
            with open(self.molecule.config.config['ansible'][
                    'inventory_file']) as instance:
                for line in instance:
                    if len(line.split()) > 1 and line.split()[0] == name:
                        ansible_host = line.split()[1]
                        conf['HostName'] = ansible_host.split('=')[1]
                        # Take the rest of the splits, split again on a single '='
                        # the first is the key, the second is the val
                        for pair in line.split()[2:]:
                            k, v = pair.split('=', 1)
                            conf[k] = v
            return conf

    def login_cmd(self, hostname):
        """
        Assemble a format template for use as a login command
        """
        cmd = 'ssh {} -i {} -l {} {}'
        return cmd

    def login_args(self, instance_name):
        """
        Determine vars to be used for the login_cmd's .format()
        """
        # Try to retrieve the SSH configuration of the host.
        conf = self.conf(name=instance_name)
        ssh_extra_args = conf.pop('ansible_ssh_extra_args', '')
        ssh_extra_args = ' '.join([
            ssh_extra_args
        ] + self.molecule.config.config['molecule']['raw_ssh_args'])

        for instance in self.instances:
            image = self._populate_image(instance)
            if instance_name == instance['name']:
                ssh_key = os.path.expanduser(
                    instance.get('IdentityFile', '~/.ssh/id_rsa'))
                ssh_user = instance.get('User', getpass.getuser())

        return [ssh_extra_args, ssh_key, ssh_user, conf['HostName']]
