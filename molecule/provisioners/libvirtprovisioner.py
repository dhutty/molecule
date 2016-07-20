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
try:
  from lxml import etree as ET
except ImportError:
    try:
        from xml.etree import cElementTree as ET
    except ImportError:
        from xml.etree import ElementTree as ET

import libvirt

from molecule import utilities
from molecule.provisioners import baseprovisioner


class LibvirtProvisioner(baseprovisioner.BaseProvisioner):
    def __init__(self, molecule):
        super(LibvirtProvisioner, self).__init__(molecule)
        self._provider = self._get_provider()
        self._platform = self._get_platform()
        self._libvirt = libvirt.open(self.m._config.config['libvirt']['uri'])

    def _get_provider(self):
        return 'libvirt'

    def _get_platform(self):
        self.m._env['MOLECULE_PLATFORM'] = 'libvirt'
        return self.m._env['MOLECULE_PLATFORM']

    @property
    def name(self):
        return 'libvirt'

    @property
    def instances(self):
        return self.m._config.config['libvirt']['instances']

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

    def _build_domain_xml(self, instance):
        """
        Builds a string of xml suitable for self._libvirt.defineXML(xml)

        :return: an xml string
        """
        utilities.print_info("\t{}: {}".format(instance['name'], instance))
        dom = ET.Element('domain', type='kvm')
        #required_elements = ['name', 'cpu', 'memory', 'os', 'features', 'devices']
        #for e in required_elements:
            #pass
            
        ET.SubElement(dom, 'name').text = instance['name']
        cpu = ET.SubElement(dom, 'cpu')
        topology = ET.SubElement(cpu, 'topology', sockets=str(instance['cpu']['sockets']), cores=str(instance['cpu']['cores']), threads=str(instance['cpu']['threads']))
        ET.SubElement(dom, 'memory', unit='MiB').text = str(instance['memory'])
        os = ET.SubElement(dom, 'os')
        ET.SubElement(os, 'type').text = 'hvm'
        boot = ET.SubElement(os, 'boot', dev='hd')
        ET.SubElement(dom, 'on_crash').text = 'restart'
        features = ET.SubElement(dom, 'features')
        for f in ['acpi', 'apic', 'pae']:
            features.append(ET.Element(f))
        
        domxml = ET.tostring(dom)
        utilities.print_info("\tXMLDesc: {}".format(domxml))
        return domxml

    def up(self, no_provision=True):
        domains = self._libvirt.listAllDomains()
        for instance in self.instances:
            # Is there an existing libvirt domain defined for this instance?
            dom_found = False
            for dom in domains:
                if not dom_found:
                    if dom.name() == instance['name']:
                        dom_found = True
                        if dom.info()[0] == 1:
                            utilities.print_info("\t{}: already running".format(instance['name']))
                            continue
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
        utilities.print_info("Destroying libvirt instances ...")
        domains = self._libvirt.listAllDomains()
        for instance in self.instances:
            utilities.print_info("\tDestroying {} ...".format(instance['name']))
            dom_found = False
            for dom in domains:
                if not dom_found:
                    if dom.name() == instance['name']:
                        dom.destroy()
                        dom.undefine()
                        utilities.print_success('\tDestroyed and undefined {}'.format(instance['name']))

    def status(self):
        states = ['no state', 'running', 'blocked', 'paused', 'being shutdown', 'shutoff', 'crashed', 'pmsuspended']
        Status = collections.namedtuple('Status', ['name', 'state'])
        status_list = []
        ins_found = False
        domains = self._libvirt.listAllDomains()
        for instance in self.instances:
            for dom in domains:
                if not ins_found:
                        if dom.name() == instance['name']:
                            ins_found = True
                            status_list.append(Status(name=instance['name'],state=states[dom.info()[0]]))
            if not ins_found:
                status_list.append(Status(name=instance['name'],state='undefined'))

        return status_list

    def conf(self):
        pass

    def _interfaces(self, domxml):
        """
        Get interfaces for an instance

        :param: domxml: the domain xml of the libvirt domain
        :return: list of dicts: [{ 'ip': '192.168.1.100', 'mac': 'AA:BB:CC:DD:EE:FF' }]
        """
        interfaces = []
        # Parse XMLDesc using ElementTree for MAC addresses
        root = ET.fromstring(domxml)
        macs = [e.get("address") for e in root.findall('./devices/interface/mac[@address]')]
        # Search the listAllNetworks() DHCPLeases() to find MAC addresses
        for net in self._libvirt.listAllNetworks():
            for mac in macs:
                for lease in net.DHCPLeases():
                    if lease['mac'] == mac:
                        interfaces.append({'ip': lease['ipaddr'], 'mac': mac})
        return interfaces

    def _ips(self, domxml):
        """
        Get a list of IP addresses
        
        :param: domxml: the domain xml of the libvirt domain
        :return: list of IP addresses
        """
        ips = []
        for interface in self._interfaces(domxml):
            ips.append(interface['ip'])
        return ips

    def inventory_entry(self, instance):
        template = self.host_template

        domains = self._libvirt.listAllDomains()
        if len(domains) == 0:
            return ''
        for dom in domains:
            if dom.name() == instance['name']:
                ips = self._ips(dom.XMLDesc())
                if len(ips) > 0:
                    return template.format(instance['name'],
                                       ips[0],
                                       instance['sshuser'])
        return ''

    def login_cmd(self, instance):
        pass

    def login_args(self, instance):
        pass
