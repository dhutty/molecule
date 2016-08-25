Provisioners
============

Molecule uses provisioners to bring up Ansible ready hosts to operate on.
Currently, Molecule supports several provisioners: Vagrant, Docker Openstack and Libvirt.

The provisioner can set when using ``init`` command or through the
``molecule.yml`` file.

Docker Provisioner
------------------

The docker provisioner is compatible with any image
that has python installed. Molecule will automatically install
python for images with the yum or apt-get package tools. A new
docker image will be built with the prefix molecule_local to separate it
from the other images on your system.

The image being used is responsible for implementing the command to execute
on ``docker run``.

Below is an example of a ``molecule.yml`` file using two containers ``foo-01`` and
``foo-02``. ``foo-01`` is running the latest image of ubuntu and ``foo-02`` is running
the latest image of ubuntu from a custom registry.

The available params for docker containers are:

* ``name`` - name of the container
* ``ansible_groups`` - groups the container belongs to in Ansible
* ``image`` - name of the image
* ``image_version`` - version of the image
* ``privileged`` - **(OPTIONAL)** whether or not to run the container in privileged mode (boolean)
* ``registry`` - **(OPTIONAL)** the registry to obtain the image
* ``install_python`` - **(default=yes)** install python onto the image being used
* ``port_bindings`` - **(OPTIONAL)** the port mapping between the Docker host and the container.
  This is passed to docker-py as the [port_bindings host config](https://github.com/docker/docker-py/blob/master/docs/port-bindings.md).
* ``volume_mounts`` - **(OPTIONAL)** the volume mappings between the Docker host and the container.
* ``command`` - **(OPTIONAL)** the command to launch the container with

The available param for the docker provisioner itself is:
* ``install_python`` - **(default=yes)** install python onto all images for all containers

Docker Example
--------------

.. code-block:: yaml

    ---
    docker:
      containers:
        - name: foo-01
          ansible_groups:
          - group1
          image: ubuntu
          image_version: latest
          privileged: True
          port_bindings:
            80: 80
        - name: foo-02
          ansible_groups:
            - group2
          image: ubuntu
          image_version: latest
          registry: testhost:5323
          volume_mounts:
            - '/this/volume:/to/this:rw'
          command: '/bin/sh'

Vagrant Provisioner
-------------------

The vagrant provisioner performs in a similar manner to the docker provisioner.
Except for using virtual machines instead of containers. Each instance of a vagrantbox
are defined inside of an instance with similar options to docker. The provisioner is
set to vagrant by default if the ``--docker`` flag is not passed when ``molecule init`` is run.

The available parameters for vagrant instances are:

* ``name`` - name of the vagrant box
* ``ansible_groups`` - groups the instance belongs to in ansible
* ``interfaces`` - network inferfaces (see ``usage``)
* ``options`` - Vagrant options supported by Molecule
* ``raw_config_args`` - Vagrant options unsupported by Molecule

Vagrant Instance Example
------------------------

This is an example of a set of vagrant instance - for information on specifying the platform/
provider, see :ref:`providers`.

.. code-block:: yaml

    ---
    instances:
      - name: vagrant-test-01
        ansible_groups:
          - group_1
        interfaces:
          - network_name: private_network
            type: dhcp
            auto_config: true
        options:
          append_platform_to_hostname: no
      - name: vagrant-test-02
        ansible_groups:
          - group_2
        interfaces:
          - network_name: private_network
            type: dhcp
            auto_config: true
        options:
          append_platform_to_hostname: no

Openstack Provisioner
---------------------

The openstack provisioner will create instances in your openstack service. The environment variables required
to use this provisioner can be found in the RC file provided on your openstack site.

The available parameters for openstack instances are:

* ``name`` - name of the openstack instance
* ``image`` - openstack image to use for instance
* ``flavor`` - openstack flavor to use for instance
* ``sshuser`` - user to access ssh with
* ``ansible_groups`` - groups the instance belongs to in ansible
* ``security_groups`` - security groups the instance belongs to in openstack

The ``keypair`` and ``keyfile`` options must also be given to specify the keypair to use when accessing your openstack
service. Usage can be seen in th example below.


Openstack instance example
--------------------------

.. code-block:: yaml

    ---
    openstack:
      keypair: KeyName
      keyfile: ~/.ssh/id_rsa
      instances:
        - name: my_instance
          image: 'CentOS 7'
          flavor: m1.xlarge
          sshuser: centos
          ansible_groups:
            - ansiblegroup

Libvirt Provisioner
---------------------

The Libvirt provisioner will create instances using the Python API for `libvirt`_ and can be configured with the following directives at the top level of `molecule.yml`:

- `uri` - the `connection string`_ to reach libvirtd.
- `networks` is a list of hashes that describe the networks that libvirt should use to connect your guest instances. Each network MUST have at least 'name' and 'cidr' keys. Each network MAY have additional keys: 'bridge' and/or 'forward' as described in the `libvirt networking`_ documentation.
    - If a `network` has a False value for the key `dhcp`, then libvirtd's network XML will **omit** the `<dhcp>` element so that the libvirtd-controlled dnsmasq process will not offer DHCP addresses to this network and you will have to take other measures such as running your own DHCP server or static assignment.
- `instances` - is a list of hashes that define the guest instances that molecule will bring up to test your role, much as for other provisioners. Each instance MUST have a subhash, `image`, with keys: `name` and `source` that defines the image that libvirt should use to boot the instance. The source MUST be URL to either a bootable qcow2 image or a vagrant box (that supports libvirt as a provider).
    - An `instance` can have a key `interfaces`, the value of which MUST be a list where each element of the list (corresponding to a network interface in the guest instance) MUST have a `network_name` which specifies which of the above `networks` the interface will be connected to. It MAY have an `address` (which libvirtd (1.2.12+) will assign to the interface); if the address is absent, molecule will attempt to DHCP an IP address for this interface.

.. _`libvirt`: http://libvirt.org
.. _`connection string`: http://libvirt.org/uri.html
.. _`libvirt networking`: https://libvirt.org/formatnetwork.html

Libvirt example
---------------

.. code-block:: yaml

    ---
    libvirt:
      uri: 'qemu:///system'
      boot_wait: 120
      images:
          - name: 'CentOS7'
            source: <url to either a qcow2 image or a vagrant box that supports libvirt as a provider>
            ssh_user: vagrant
            ssh_key: '~/.vagrant.d/insecure_private_key'
          - name: 'trusty64'
            source: 'https://example.com/ubuntu/boxes/trusty64/trusty64.img'
            ssh_user: vagrant
            ssh_key: '~/.vagrant.d/insecure_private_key'
      networks:
          - name: default
            forward: nat
            cidr: 192.168.122.1/24
          - name: molecule0
            cidr: 192.168.123.1/24
            forward: none

      instances:
        - name: my_minimal_instance
          image:
            name: 'CentOS7'
          interfaces:
            - network_name: default
        - name: my_configured_instance
          ansible_groups:
            - example-group
            - example-group1
          image:
            name: 'trusty64'
            source: 'https://example.com/ubuntu/boxes/trusty64/trusty64.img'
            ssh_user: vagrant
            ssh_key: '~/.vagrant.d/insecure_private_key'
          interfaces:
            - network_name: default
              address: 192.168.122.10
            - network_name: molecule0
          cpu:
            sockets: 1
            cores: 1
            threads: 2
          memory: 1024


Implementing Provisioners
-------------------------

The short description for implementing a provisioner is to implement the interface defined in the BaseProvisioner class.
