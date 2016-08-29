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
from pprint import pprint as pp
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

from molecule import utilities
LOG = utilities.get_logger(__name__)

try:
    import guestfs
    GUESTFS = True
except ImportError:
    GUESTFS = False
    LOG.warning(
        "\tPython module for libguestfs not available, certain networking-related functionality unavailable")

from jinja2 import Template
import libvirt
import netaddr
import requests

from molecule.provisioners import baseprovisioner


class LibvirtProvisioner(baseprovisioner.BaseProvisioner):
    """
    Implements a Molecule provisioner that uses libvirt to provision instances.
    """

    def __init__(self, molecule):
        super(LibvirtProvisioner, self).__init__(molecule)
        self._lvconfig = self.molecule.config.config['libvirt']
        self._provider = self._get_provider()
        self._platform = self._get_platform()
        self._libvirt = libvirt.open(self._lvconfig['uri'])
        self._pool_path = os.path.expanduser(
            os.path.join('/opt/jenkins', 'libvirt', 'images'))
        self._sources_path = os.path.expanduser(
            os.path.join('/opt/jenkins', 'libvirt', 'sources'))
        for path in [self._pool_path, self._sources_path]:
            if not os.path.exists(path):
                os.makedirs(path, 0775)
        self._boot_wait = int(self._lvconfig.get('boot_wait', 90))

    def _get_provider(self):
        return 'libvirt'

    def _get_platform(self):
        return self.default_platform

    @property
    def name(self):
        return 'libvirt'

    @property
    def instances(self):
        return self._lvconfig['instances']

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
        return {
            'ansible-inventory':
            self.molecule.config.config['ansible']['inventory_file'],
            'connection': 'ansible'
        }

    @property
    def serverspec_args(self):
        return dict()

    @property
    def ansible_connection_params(self):
        return {'connection': 'ssh'}

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

        :param pool_name: name for the pool
        """
        try:
            pool_found = self._libvirt.storagePoolLookupByName(pool_name)
            if pool_found and not pool_found.isActive():
                pool_found.create()
            return pool_found  # existing pool is now running
        except libvirt.libvirtError:
            return self._define_pool(pool_name)

    def _define_network(self, network):
        """
        Define a libvirt network and start it.

        :param network: a dict describing the network, with at least a 'name' and a 'cidr'
        :return: a Libvirt Network object

        TODO: Make this all configurable. 'network' will be a dict that describes a libvirt network, populated based on molecule.yml.
        libvirt:
            networks:
                - name: molecule0
                  forward: nat|none
                  #bridge: virbr10
                  cidr: 192.168.121.1/24
        """
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
        cidr_net = netaddr.IPNetwork(network['cidr'])
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

        :param network: a dict describing the network, with unique 'name' and 'cidr' keys
        :return: a Libvirt Network object
        """
        # TODO: Remove this when we have molecule defaults for libvirt networks
        if not network:
            network = {'name': 'molecule0',
                       'forward': 'nat',
                       # 'bridge': 'virbr10',
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

        :param instance: a dict that describes an instance (a virtualization guest that this provisioner should create)
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
            if 'address' in nic:
                ip = netaddr.IPAddress(nic['address'])
                # Find the libvirt network for this interface is connected to
                cidr = netaddr.IPNetwork(
                    filter(lambda net: net['name'] == nic['network_name'],
                           self._lvconfig['networks'])[0]['cidr'])
                ET.SubElement(
                    iface,
                    'ip',
                    address=nic['address'],
                    prefix=str(cidr.prefixlen))
                ET.SubElement(
                    iface,
                    'route',
                    family='ipv4',
                    address=str(cidr.network),
                    prefix=str(cidr.prefixlen),
                    gateway=str(cidr.ip))
            ET.SubElement(iface, 'source', network=nic['network_name'])
            ET.SubElement(iface, 'model', type='virtio')
        # Finally
        domxml = ET.tostring(dom)
        LOG.debug("\tXMLDesc: {}".format(domxml))
        return domxml

    def _fetch(self, url, filename):
        """
        Fetches a URL, saves response to <filename>.

        :param url: URL to fetch
        :param filename: destination filename, will be in either self._sources_path or self._pool_path
        """
        path = self._sources_path if filename.endswith(
            '.box') else self._pool_path
        utilities.print_info("Fetching image {} \n\t to {}...".format(
            url, os.path.join(path, filename)))
        r = requests.get(url, stream=True)
        if r.status_code != 200:
            try:
                os.remove(os.path.join(path, filename))
            except OSError:
                pass
            r.raise_for_status()
        with open(os.path.join(path, filename), 'wb') as fd:
            for chunk in r.iter_content(chunk_size=4096):
                fd.write(chunk)

    def _unpack_box(self, image, imagefile):
        """
        Extract the qcow2 image file from a Vagrant box into a libvirt storage pool so it can be used as a backing store.

        :param image: a dict of the 'name' and 'source' URL for the image
        :param imagefile: path to the box file
        """
        # A vagrant box is actually just a .tar.gz from which we need to extract the .img
        boxfile = os.path.join(self._sources_path, imagefile)
        utilities.print_info("Unpacking boxfile {} ...".format(boxfile))
        targz = tarfile.open(boxfile, mode='r:gz')
        members = [member for member in targz.getmembers()
                   if member.name.endswith('.img')]
        for member in members:
            targz.extract(member, self._pool_path)
            os.rename(
                os.path.join(self._pool_path, member.name),
                os.path.join(self._pool_path, image['name'] + '.img'))

    def _create_volume(self, pool, instance):
        """
        Create a libvirt storage volume for an instance

        :param pool: Libvirt Storage Pool object
        :param instance: a dict that describes an instance
        """
        utilities.print_info("Creating libvirt volume for instance {}".format(
            instance['name']))
        vol = ET.Element('volume', type='file')
        ET.SubElement(vol, 'name').text = instance['name'] + '.img'
        ET.SubElement(vol, 'capacity', unit='GiB').text = '40'
        target = ET.SubElement(vol, 'target')
        ET.SubElement(target, 'format', type='qcow2')
        permissions = ET.SubElement(target, 'permissions')
        # TODO: FIXME: Glaring security hole for anyone who does not trust every user on the system running libvirt
        ET.SubElement(permissions, 'mode').text = '0666'
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

        :param pool: Libvirt Storage Pool object
        :param instance: a dict that describes an instance
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
        """
        Get this instance's image config.

        Any config specified for this instance is merged with (overriding) any config that already exists for an image of the same name.

        :param instance: an instance dict
        :return: the final image dict for that instance
        """

        image = instance.get('image', self._lvconfig['images'][0])
        default_image = next(ref_image
                             for ref_image in self._lvconfig['images']
                             if ref_image['name'] == image['name'])
        for key in ['source', 'ssh_user', 'ssh_key']:
            image.setdefault(key, default_image[key])
        return image

    def up(self, no_provision=True):
        """
        Up or define/up libvirt instances.

        :param no_provision: is not meaningful for libvirt instances
        """
        for net in self._lvconfig['networks']:
            self._up_network(net)
        pool = self._up_pool()
        domains = self._libvirt.listAllDomains()
        wait = True
        for inst_index, instance in enumerate(self.instances):
            # Ensure our first interface is on the 'default' network
            if instance['interfaces'][0]['network_name'] != 'default':
                instance['interfaces'].insert(0, {'network_name': 'default'})
            image = self._populate_image(instance)
            self.instances[inst_index]['image'] = image
            imagefile = image['source'].split('/')[-1]
            # Ensure that the image is available
            image_path = os.path.join(self._pool_path, image['name'] + '.img')
            source_path = os.path.join(self._sources_path, imagefile)
            if not os.path.exists(image_path):
                if not os.path.exists(source_path):
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
            dom = next((domain for domain in domains
                        if domain.name() == instance['name']), None)
            if dom:
                if dom.info()[0] == 1:
                    utilities.print_info("\t{}: already running".format(
                        instance['name']))
                    continue
                else:
                    utilities.print_info("\t{}: booting".format(instance[
                        'name']))
                    dom.create()
                    if wait:
                        time.sleep(self._boot_wait)
                    continue
            else:
                utilities.print_info("\t{}: defining".format(instance['name']))
                dom = self._libvirt.defineXML(self._build_domain_xml(instance))
                if not GUESTFS:
                    LOG.warning(
                        "\tlibguestfs not available, cannot autoconfigure guest NICs")
                else:
                    # TODO: Here is the point at which to modify with libguestfs,
                    #  i.e. after creating the domain's volume but before booting the domain.
                    # if any of this instance's interfaces has a key 'address'? or always?
                    try:
                        guest = guestfs.GuestFS(python_return_dict=True)
                        self._manipulate_guest_image(guest, instance)
                        guest.umount_all()
                        guest.shutdown()
                        guest.close()
                    except Exception, e:
                        LOG.warning(
                            "\nFAILED to manipulate the guest image so could not configure network interfaces: {}".format(
                                e))
                utilities.print_success("\tDefined instance {}.\n".format(
                    instance['name']))
                try:
                    utilities.print_info("\t{}: booting".format(instance[
                        'name']))
                    dom.create()
                    if wait:
                        time.sleep(self._boot_wait)
                except libvirt.libvirtError as e:
                    LOG.error("\nFailed to create/boot {}: {}".format(instance[
                        'name'], e))
                    dom.undefine()
                    raise libvirt.libvirtError(e)
            # DHCP interfaces
            for iface in instance['interfaces']:
                ip = self._configure_interface(iface, dom)
                if not ip and iface[
                        'network_name'] != 'default':  # If we still don't have an IP, try harder (only for non-default networks, because we have to login)
                    try:
                        self._login_configure_network(instance)
                    except:
                        pass  # Give up:)

    def _configure_interface(self, iface, dom):
        """
        :param iface: an interface dict, with at least a 'network_name'
        :param dom: a libvirt domain object
        :return: the IP addresss
        """
        # If the network address is static:
        if 'address' in iface:
            return iface['address']
        # If it's DHCP
        ip = self._get_ip(self._macs(dom, iface['network_name']))
        if not ip:  # If we don't have an IP yet, get one
            iface['mac'] = self._macs(dom, iface['network_name'])
            ip = self._lease_ip(iface)
        return ip

    def _login_config_network(self, instance):
        """
        Login to guest, try to configure network.
        :param instance: the instance dict
        :return:
        """
        # By this point, we should have waited for each NIC to dhcp, any that don't have IPs should be dhcliented
        for index, iface in enumerate(instance['interfaces']):
            pp(instance['interfaces'])
            if iface['network_name'] == 'default':
                continue
            if 'address' not in iface:
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
                            instance['ip'], os.path.expanduser(instance[
                                'image']['ssh_key']), instance['image'][
                                    'ssh_user'],
                            '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null')))
                device = ''.join(['eth', str(index)])
                # Check for redhat-derivative && NetworkManager? => use nmcli
                rh_derivative = False
                try:
                    rh_check_cmd = cmd + ['pgrep', '-a', 'NetworkManager']
                    rh_derivative = subprocess.check_output(rh_check_cmd)
                except subprocess.CalledProcessError, e:
                    pass

                if rh_derivative:
                    cmd.append(' '.join(
                        ['pgrep', '-a', 'dhclient', '|', 'grep', device, '||',
                         'sudo', '/usr/bin/nmcli', 'con', 'add', 'type',
                         'ethernet', 'con-name', 'molecule-' + device,
                         'ifname', device]))
                else:
                    # Not redhat-derivative or no NetworkManager? => run dhclient.
                    # This should take care of *at least* debian-derivatives, likely other linux distros and some other *nix
                    cmd.append(' '.join(
                        ['pgrep', '-a', 'dhclient', '|', 'grep', device, '||',
                         'sudo', 'dhclient', device]))
                utilities.print_info(
                    "\tRunning dhclient for interface {} on instance: {}".format(
                        iface['network_name'], instance['name']))
                try:
                    res = subprocess.check_output(
                        cmd, stderr=subprocess.STDOUT)
                except subprocess.CalledProcessError, e:
                    pass
#         # Update self._lvconfig['instances'] with HostName from 'default' interface
#         if 'ip' in instance:
#             instance['HostName'] = instance['ip']
#         else:
#             instance['HostName'] = self._lease_ip(
#                 {'network_name': 'default',
#                  'mac': self._macs(dom, 'default')})
#         for index, inst in enumerate(self.molecule.config.config[
#                 'libvirt']['instances']):
#             if inst['name'] == instance['name']:
#                 self._lvconfig['instances'][index].update(instance)
#         instance['User'] = instance['image']['ssh_user']
#         instance['IdentityFile'] = os.path.expanduser(instance[
#             'image']['ssh_key'])
#         # Write a ssh-config based on state
#         kwargs = {'instances': self.instances}
#         LOG.debug("\tWriting ssh_config using: {}".format(kwargs))
#         utilities.write_template(
#             self.molecule.config.config['molecule'][
#                 'ssh_config_template'], '.molecule/ssh_config',
#             kwargs=kwargs)

    def _manipulate_guest_image(self, guest, instance):
        """
        Ensure that each network interface that libvirt creates has
        (necessarily distro-specific) network configuration that either
        a) specifies IP config (according to the instance's interfaces' address)
        OR
        b) ensures that the guest is configured to DHCP for each interface

        :param guest: a GuestFS (for this instance/volume)
        :param instance: an instance dict (so we can determine the desired network config)
        """
        drive = self._pool_path + '/' + instance['name'] + '.img'
        guest.add_drive_opts(drive, readonly=0)
        LOG.info("\tLaunching libguestfs to edit {}".format(drive))
        guest.launch()
        # Ask libguestfs to inspect for operating systems.
        roots = guest.inspect_os()
        if len(roots) == 0:
            raise (Error("inspect_vm: no operating systems found"))
        distro = ''
        for root in roots:
            distro = guest.inspect_get_distro(root)
            # Sort keys by length, shortest first, so that we end up
            # mounting the filesystems in the correct order.
            mps = guest.inspect_get_mountpoints(root)
            for device in sorted(mps, key=len):
                try:
                    guest.mount(mps[device], device)
                except RuntimeError as msg:
                    print "%s (ignored)" % msg
        LOG.info("\tlibguestfs found {}".format(distro))

        nameservers = self._lvconfig.get('nameservers', ['8.8.8.8'])
        resolv_template = Template(
            "{% for ns in nameservers %}nameserver {{ ns }}\n{% endfor %}")
        guest.write(
            "/etc/resolv.conf",
            resolv_template.render(nameservers=nameservers))
        if distro.startswith('redhat-based') or distro.startswith('rhel'):
            template = Template(
                "{% for k,v in iface_def.iteritems() %}{{ k }}={{ v }}\n{% endfor %}")
            for iface_index, iface in enumerate(instance['interfaces']):
                text = template.render(
                    iface_def=self._generate_el_network_config(iface_index,
                                                               iface))
                LOG.debug("\tWriting \n {}".format(text))
                guest.write("/etc/sysconfig/network-scripts/ifcfg-eth" +
                            str(iface_index), text)
        elif distro.startswith('debian') or distro.startswith('ubuntu'):
            for iface_index, iface in enumerate(instance['interfaces']):
                if 'address' in iface:
                    template = Template(
                        "iface eth" + str(iface_index) +
                        "inet static\n\t{% for k,v in iface_def.iteritems() %}\n{{ k }} {{ v }}\n{% endfor %}")
                else:
                    template = Template("iface eth" + str(iface_index) +
                                        "inet dhcp")
                text = template.render(
                    iface_def=self._generate_deb_network_config(iface_index,
                                                                iface))
                LOG.debug("\tWriting \n {}".format(text))
                guest.write("/etc/network/interfaces.d/eth" + str(iface_index),
                            text)
        else:
            LOG.warning(
                "\tMolecule only supports manipulating networking config with libguestfs for redhat-derivative or debian derivative linux distributions")

    def _generate_deb_network_config(self, iface_index, iface):
        """
        Calculate Debian-distro network config

        :param iface_index: ordinal for which interface (integer)
        :param iface: the interface dict
        :return: a dict suitable for feeding to the NIC config template
        """
        # Find the libvirt network for this interface is connected to
        # cidr = netaddr.IPNetwork(next((net for net in self._lvconfig['networks'] if net['name'] == iface['network_name'])))
        cidr = netaddr.IPNetwork(
            filter(lambda net: net['name'] == iface['network_name'],
                   self.molecule.config.config['libvirt']['networks'])[0][
                       'cidr'])
        iface_def = {}
        if 'address' in iface:  # i.e. Static
            iface_def['address'] = iface['address']
            iface_def['netmask'] = str(cidr.netmask)
            iface_def['broadcast'] = str(cidr.broadcast)
            iface_def['network'] = str(cidr.network)
            iface_def['gateway'] = str(cidr.ip)
        return iface_def

    def _generate_el_network_config(self, iface_index, iface):
        """
        Calculate EL(7?)-based distro network config

        :param iface_index: ordinal for which interface (integer)
        :param iface: the interface dict
        :return: a dict suitable for feeding to the NIC config template
        """
        # Find the libvirt network for this interface is connected to
        # cidr = netaddr.IPNetwork(next((net for net in self._lvconfig['networks'] if net['name'] == iface['network_name'])))
        cidr = netaddr.IPNetwork(
            filter(lambda net: net['name'] == iface['network_name'],
                   self.molecule.config.config['libvirt']['networks'])[0][
                       'cidr'])
        iface_def = {
            'NAME': 'eth' + str(iface_index),
            'DEVICE': 'eth' + str(iface_index),
            'ONBOOT': 'yes',
            'TYPE': 'Ethernet',
        }
        if iface_index == 0:
            iface_def['DEFROUTE'] = 'yes'
            iface_def['GATEWAY'] = str(cidr.ip)

        if 'address' in iface:
            iface_def['BOOTPROTO'] = 'none'
            iface_def['IPADDR'] = iface['address']
            iface_def['PREFIX'] = str(cidr.prefixlen)
        else:
            iface_def['BOOTPROTO'] = 'dhcp'
        return iface_def

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
                        try:
                            dom.destroy()
                        except:
                            pass
                        try:
                            self._destroy_volume(pool, instance)
                        except:
                            pass
                        try:
                            dom.undefine()
                        except:
                            pass
                            # TODO: Consider whether these should really cause molecule to exit fail?
                        utilities.print_success(
                            '\tDestroyed and undefined libvirt instance {}'.format(
                                instance['name']))
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
            dom = next((domain for domain in domains
                        if domain.name() == instance['name']), None)
            if dom:
                status_list.append(
                    Status(
                        name=instance['name'],
                        state=states[dom.info()[0]],
                        provider='Libvirt'))
            else:
                status_list.append(
                    Status(
                        name=instance['name'],
                        state='undefined',
                        provider='Libvirt'))

        return status_list

    def _lease_ip(self, interface):
        """
        Lease IP address

        :param interface: an interface dict that has at least: {'mac': MAC address, 'network_name': (libvirt) name of network}
        :return: an IP address
        """
        delay = 1
        max_count = 6
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

        :param domain: a libvirt domain object
        :return: list of interfaces
        """
        dom = ET.fromstring(domain.XMLDesc())
        nics = [e for e in dom.findall('./devices/interface[mac]')]
        return nics

    def _get_ip(self, mac):
        """
        Search libvirt's networks' leases for this MAC, return its IP address

        :param mac: a MAC address, formatted as in libvirt's XML: 'AA:BB:CC:DD:EE:FF'
        :return: an IPv4 address
        """
        nets = self._libvirt.listAllNetworks()
        leases = sum((net.DHCPLeases() for net in nets), [])
        return next((lease['ipaddr'] for lease in leases
                     if lease['mac'] == mac), None)

    def _macs(self, domain, network):
        """
        Get a Domain's MAC addresses for a particular network.

        :param domain: a libvirt domain object
        :param network: the name of the network
        :return: a MAC address that this domain has on the specified network
        """
        macs = []
        nics = self._nics(domain)
        for nic in nics:
            mac = nic.find('./mac[@address]').get("address")
            source_net = nic.find('./source[@network]').get("network")
            if source_net == network:
                macs.append(mac)
        if macs:
            return macs[
                0]  # Assumes a single MAC for this instance on this network: probably valid
        else:
            return None

    def inventory_entry(self, instance):
        """
        Generate an Ansible inventory entry for an instance

        This method gets called by create AND by converge, so it cannot rely on instance config that is defined by create unless that has been propagated into molecule.yml (or state.yml?)
        :param instance: an instance dict
        :return: a string that is Ansible inventory
        """
        template = self.host_template
        # TODO: replace with using "proper" defaults
        instance['interfaces'] = instance.get('interfaces',
                                              [{'network_name': 'default'}])

        # Ensure our first interface is on the 'default' network
        if instance['interfaces'][0]['network_name'] != 'default':
            instance['interfaces'].insert(0, {'network_name': 'default'})
        domains = self._libvirt.listAllDomains()
        image = self._populate_image(instance)
        if len(domains) == 0:
            return ''
        dom = next((domain for domain in domains
                    if domain.name() == instance['name']), None)
        if not dom:
            LOG.error("No libvirt domain found for {}".format(instance[
                'name']))
            return template.format(instance['name'], None,
                                   os.path.expanduser(image['ssh_key']),
                                   image['ssh_user'])

        iface = next((iface for iface in instance['interfaces']
                      if iface['network_name'] == 'default'), None)
        image = self._populate_image(instance)
        ip = self._configure_interface(iface, dom)
        # TODO: Push the discovered IP into self.instances[me]['ip']
        return template.format(instance['name'], ip, image['ssh_key'],
                               image['ssh_user'])
#         for index, iface in enumerate(instance['interfaces']):
#             instance['interfaces'][index]['mac'] = self._macs(
#                 dom, iface['network_name'])[
#                     0]
#             instance['interfaces'][index]['address'] = iface.get(
#                 'address', self._get_ip(iface['mac']))
#             if instance['interfaces'][index]['address']:
#                 utilities.print_success(
#                     "\t\tIP found for mac {} on network: {}: {}".format(
#                         iface['mac'], iface['network_name'], instance[
#                             'interfaces'][index]['address']))
#                 entry = template.format(
#                     instance['name'],
#                     instance['interfaces'][index]['address'],
#                     image['ssh_key'], image['ssh_user'])
#                 # TODO: This means the network named 'default' is special and must be present
#                 if iface['network_name'] == 'default':
#                     instance['ip'] = instance['interfaces'][index][
#                         'address']
#                 break
#             instance['interfaces'][index]['address'] = self._lease_ip(
#                 iface)
#             if instance['interfaces'][index]['address']:
#                 # TODO: This means the network named 'default' is special and must be present
#                 if iface['network_name'] == 'default':
#                     entry = template.format(
#                         instance['name'],
#                         instance['interfaces'][index]['address'],
#                         os.path.expanduser(image['ssh_key']),
#                         image['ssh_user'])
#                     instance['ip'] = instance['interfaces'][index][
#                         'address']
#                     break
#         return entry

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

        :param hostname: the host to login to
        :return: a 'format' template
        """
        cmd = 'ssh {} -i {} -l {} {}'
        return cmd

    def login_args(self, instance_name):
        """
        Determine vars to be used for the login_cmd's .format()

        :param instance_name: the name of the instance
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


class NetworkConfig():
    def __init__(self, distro):
        pass
