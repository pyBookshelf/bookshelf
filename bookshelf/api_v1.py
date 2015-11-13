# vim: ai ts=4 sts=4 et sw=4 ft=python fdm=indent et foldlevel=0

import boto.ec2
import json
import os
import pyrax
import re
import socket
import sys
import uuid

from boto.ec2.blockdevicemapping import BlockDeviceMapping, EBSBlockDeviceType
from fabric.api import env, sudo, local, settings, run
from fabric.operations import (get as get_file,
                               put as upload_file)
from fabric.colors import green, yellow, red
from fabric.context_managers import cd, hide, lcd
from fabric.contrib.files import (append as file_append,
                                  contains as file_contains,
                                  comment as comment_line,
                                  exists,
                                  sed,
                                  contains)
from itertools import chain
from sys import exit
from time import sleep


def add_epel_yum_repository():
    """ Install a repository that provides epel packages/updates """
    yum_install(packages=["epel-release"])


def add_firewalld_service(service, permanent=True):
    """ adds a firewall rule """
    yum_install(packages=['firewalld'])

    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=True, capture=True):
        p = ''
        if permanent:
            p = '--permanent'
        sudo('firewall-cmd --add-service %s %s' % (service, p))
        sudo('systemctl reload firewalld')


def add_firewalld_port(port, permanent=True):
    """ adds a firewall rule """

    yum_install(packages=['firewalld'])

    log_green('adding a new fw rule: %s' % port)
    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=True, capture=True):
        p = ''
        if permanent:
            p = '--permanent'
        sudo('firewall-cmd --add-port %s %s' % (port, p))
        sudo('systemctl restart firewalld')


def add_usr_local_bin_to_path():
    """ adds /usr/local/bin to $PATH """

    log_green('inserts /usr/local/bin into PATH')
    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=True, capture=True):
        sudo('echo "export PATH=/usr/local/bin:$PATH" '
             '|sudo /usr/bin/tee /etc/profile.d/fix-path.sh')


def add_zfs_apt_repository():
    with settings(hide('warnings', 'running', 'stdout'),
                  warn_only=True, capture=True):
        install_ubuntu_development_tools()
        apt_install(packages=['dkms',
                              'linux-headers-generic',
                              'build-essential'])
        sudo('echo | add-apt-repository ppa:zfs-native/stable')
        sudo('apt-get update')


def add_zfs_yum_repository():
    """ adds the yum repository for ZFSonLinux """
    ZFS_REPO_PKG = (
        "http://archive.zfsonlinux.org/epel/zfs-release.el7.noarch.rpm"

    )
    yum_install_from_url('zfs-release', ZFS_REPO_PKG)


def apt_install(**kwargs):
    """
        installs a apt package
    """
    for pkg in list(kwargs['packages']):
        if is_package_installed(distribution='ubuntu', pkg=pkg) is False:
            log_green("installing %s ..." % pkg)
            sudo("apt-get install -y %s" % pkg)


def apt_install_from_url(pkg_name, url, log=False):
    """ installs a pkg from a url
        p pkg_name: the name of the package to install
        p url: the full URL for the rpm package
    """
    if is_package_installed(distribution='ubuntu', pkg=pkg_name) is False:

        if log:
            log_green("installing %s from %s" % (pkg_name, url))

        with settings(hide('warnings', 'running', 'stdout'),
                      warn_only=True, capture=True):

            sudo("wget -c -O %s.deb %s" % (pkg_name, url))
            result = sudo("dpkg -i %s.deb" % pkg_name)
            if result.return_code == 0:
                return True
            elif result.return_code == 1:
                return False
            else:  # print error to user
                print(result)
                raise SystemExit()


def apt_add_repository_from_apt_string(apt_string, apt_file):
    """ adds a new repository file for apt """

    apt_file_path = '/etc/apt/sources.list.d/%s' % apt_file

    if not file_contains(apt_file_path, apt_string.lower(), use_sudo=True):
        file_append(apt_file_path, apt_string.lower(), use_sudo=True)

        with hide('running', 'stdout'):
            sudo("apt-get update")


def apt_add_key(keyid, keyserver='keyserver.ubuntu.com', log=False):
    """ trust a new PGP key related to a apt-repository """
    if log:
        log_green('trusting keyid %s from %s' % (keyid, keyserver))
    with settings(hide('warnings', 'running', 'stdout')):
        sudo('apt-key adv --keyserver %s --recv %s' % (keyserver, keyid))


def arch():
    """ returns the current cpu archictecture """
    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=True, capture=True):
        result = sudo('rpm -E %dist').strip()
    return result


def cache_docker_image_locally(docker_image):
    # download docker images to speed up provisioning
    log_green('pulling docker image %s locally' % docker_image)
    sudo("docker pull %s" % docker_image)


def connect_to_ec2(region, access_key_id, secret_access_key):
    """ returns a connection object to AWS EC2  """
    conn = boto.ec2.connect_to_region(region,
                                      aws_access_key_id=access_key_id,
                                      aws_secret_access_key=secret_access_key)
    return conn


def connect_to_rackspace(region,
                         access_key_id,
                         secret_access_key):
    """ returns a connection object to Rackspace  """
    pyrax.set_setting('identity_type', 'rackspace')
    pyrax.set_default_region(region)
    pyrax.set_credentials(access_key_id, secret_access_key)
    nova = pyrax.connect_to_cloudservers(region=region)
    return nova


def create_ami(region,
               access_key_id,
               secret_access_key,
               instance_id,
               name,
               description,
               block_device_mapping=None):
    conn = connect_to_ec2(region, access_key_id, secret_access_key)
    ami = conn.create_image(instance_id,
                            name,
                            description,
                            block_device_mapping)

    image_status = conn.get_image(ami)
    while (image_status.state != "available" and
           image_status.state != "failed"):
        log_yellow('creating ami...')
        sleep_for_one_minute()
        image_status = conn.get_image(ami)

    if image_status.state == "available":
        log_green("ami %s %s" % (ami, image_status))
        return(ami)
    else:
        log_red("ami %s %s" % (ami, image_status))
        return False


def create_image(cloud,
                 region,
                 access_key_id,
                 secret_access_key,
                 instance_id,
                 name,
                 description,
                 block_device_mapping=None):
    """ proxy call for ec2, rackspace create ami backend functions """
    if cloud == 'ec2':
        return(create_ami(region,
                          access_key_id,
                          secret_access_key,
                          instance_id,
                          name,
                          description,
                          block_device_mapping=None))

    if cloud == 'rackspace':
        return(create_rackspace_image(region,
                                      access_key_id,
                                      secret_access_key,
                                      instance_id,
                                      name,
                                      description,
                                      block_device_mapping=None))


def create_rackspace_image(region,
                           access_key_id,
                           secret_access_key,
                           server_id,
                           name,
                           description,
                           block_device_mapping=None):

    nova = connect_to_rackspace(region, access_key_id, secret_access_key)

    image_id = nova.servers.create_image(server_id, name)
    image = nova.images.get(image_id).status.lower()
    log_green('creating rackspace image...')
    while nova.images.get(image_id).status.lower() not in ['active', 'error']:
        log_green('building rackspace image...')
        sleep_for_one_minute()

    if image == 'error':
        log_red('error creating image')
        sys.exit(1)

    log_green('finished image: %s' % image_id)
    return image_id


def create_docker_group():
    """ creates the docker group """
    if not contains('/etc/group', 'docker', use_sudo=True):
        sudo("groupadd docker")


def create_server(cloud,
                  region,
                  access_key_id,
                  secret_access_key,
                  distribution,
                  disk_name,
                  disk_size,
                  ami,
                  key_pair,
                  instance_type,
                  username,
                  security_groups='',
                  instance_name='',
                  tags={}):
    """
        Create a new instance
    """
    if cloud == 'ec2':
        create_server_ec2(distribution,
                          region,
                          access_key_id,
                          secret_access_key,
                          disk_name,
                          disk_size,
                          ami,
                          key_pair,
                          instance_type,
                          username,
                          tags,
                          security_groups)
    if cloud == 'rackspace':
        create_server_rackspace(distribution=distribution,
                                region=region,
                                access_key_id=access_key_id,
                                secret_access_key=secret_access_key,
                                disk_name=disk_name,
                                disk_size=disk_size,
                                ami=ami,
                                key_pair=key_pair,
                                instance_type=instance_type,
                                username=username,
                                tags=tags,
                                instance_name=instance_name,
                                security_groups=security_groups)


def create_server_ec2(distribution,
                      region,
                      access_key_id,
                      secret_access_key,
                      disk_name,
                      disk_size,
                      ami,
                      key_pair,
                      instance_type,
                      username,
                      tags={},
                      security_groups=None):
    """
    Creates EC2 Instance and saves it state in a local json file
    """
    #
    conn = connect_to_ec2(region, access_key_id, secret_access_key)

    log_green("Started...")
    log_yellow("...Creating EC2 instance...")

    # we need a larger boot device to store our cached images
    ebs_volume = EBSBlockDeviceType()
    ebs_volume.size = disk_size
    bdm = BlockDeviceMapping()
    bdm[disk_name] = ebs_volume

    # get an ec2 ami image object with our choosen ami
    image = conn.get_all_images(ami)[0]
    # start a new instance
    reservation = image.run(1, 1,
                            key_name=key_pair,
                            security_groups=security_groups,
                            block_device_map=bdm,
                            instance_type=instance_type)

    # and get our instance_id
    instance = reservation.instances[0]

    #  and loop and wait until ssh is available
    while instance.state == u'pending':
        log_yellow("Instance state: %s" % instance.state)
        sleep(10)
        instance.update()
    log_green("Instance state: %s" % instance.state)
    wait_for_ssh(instance.public_dns_name)

    # update the EBS volumes to be deleted on instance termination
    for dev, bd in instance.block_device_mapping.items():
        instance.modify_attribute('BlockDeviceMapping',
                                  ["%s=%d" % (dev, 1)])

    # add a tag to our instance
    conn.create_tags([instance.id], tags)

    log_green("Public dns: %s" % instance.public_dns_name)
    # finally save the details or our new instance into the local state file
    save_state_locally(cloud='ec2',
                       instance_id=instance.id,
                       region=region,
                       username=username,
                       access_key_id=access_key_id,
                       secret_access_key=secret_access_key)


def create_server_rackspace(distribution,
                            region,
                            access_key_id,
                            secret_access_key,
                            disk_name,
                            disk_size,
                            ami,
                            key_pair,
                            instance_type,
                            username,
                            instance_name,
                            tags={},
                            security_groups=None):
    """
    Creates Rackspace Instance and saves it state in a local json file
    """
    nova = connect_to_rackspace(region, access_key_id, secret_access_key)
    log_yellow("Creating Rackspace instance...")

    flavor = nova.flavors.find(name=instance_type)
    image = nova.images.find(name=ami)

    server = nova.servers.create(name=instance_name,
                                 flavor=flavor.id,
                                 image=image.id,
                                 region=region,
                                 availability_zone=region,
                                 key_name=key_pair)

    while server.status == 'BUILD':
        log_yellow("Waiting for build to finish...")
        sleep(5)
        server = nova.servers.get(server.id)

    # check for errors
    if server.status != 'ACTIVE':
        log_red("Error creating rackspace instance")
        exit(1)

    # the server was assigned IPv4 and IPv6 addresses, locate the IPv4 address
    ip_address = server.accessIPv4

    if ip_address is None:
        log_red('No IP address assigned')
        exit(1)

    wait_for_ssh(ip_address)
    log_green('New server with IP address {0}.'.format(ip_address))
    # finally save the details or our new instance into the local state file
    save_state_locally(cloud='rackspace',
                       instance_id=server.id,
                       region=region,
                       username=username,
                       access_key_id=access_key_id,
                       secret_access_key=secret_access_key)


def dir_attribs(location, mode=None, owner=None,
                group=None, recursive=False, use_sudo=False):
    """ cuisine dir_attribs doesn't do sudo, so we implement our own
        Updates the mode/owner/group for the given remote directory."""
    recursive = recursive and "-R " or ""
    if mode:
        if use_sudo:
            sudo('chmod %s %s %s' % (recursive, mode,  location))
        else:
            run('chmod %s %s %s' % (recursive, mode,  location))
    if owner:
        if use_sudo:
            sudo('chown %s %s %s' % (recursive, owner, location))
        else:
            run('chown %s %s %s' % (recursive, owner, location))
    if group:
        if use_sudo:
            sudo('chgrp %s %s %s' % (recursive, group, location))
        else:
            run('chgrp %s %s %s' % (recursive, group, location))


def dir_ensure(location, recursive=False, mode=None,
               owner=None, group=None, use_sudo=False):
    """ cuisine dir_ensure doesn't do sudo, so we implement our own
    Ensures that there is a remote directory at the given location,
    optionally updating its mode/owner/group.
    If we are not updating the owner/group then this can be done as a single
    ssh call, so use that method, otherwise set owner/group after creation."""

    args = ''
    if recursive:
        args = args + ' -p '

    if not dir_exists(location):
        if use_sudo:
            sudo('mkdir %s %s' % (args, location))
        else:
            run('mkdir %s %s' % (args, location))

    if owner or group or mode:
        if use_sudo:
            dir_attribs(location,
                        owner=owner,
                        group=group,
                        mode=mode,
                        recursive=recursive,
                        use_sudo=True)
        else:
            dir_attribs(location,
                        owner=owner,
                        group=group,
                        mode=mode,
                        recursive=recursive)


def dir_exists(location):
    """Tells if there is a remote directory at the given location."""
    return run('test -d %s && echo OK ; true' % (location))


def disable_env_reset_on_sudo():
    """ updates /etc/sudoers so that users from %wheel keep their
        environment when executing a sudo call
    """
    log_green('disabling env reset on sudo')
    file_append('/etc/sudoers',
                'Defaults:%wheel !env_reset,!secure_path', use_sudo=True)


def disable_requiretty_on_sudoers():
    """ allow sudo calls through ssh without a tty """
    log_green('disabling requiretty on sudo calls')
    comment_line('/etc/sudoers',
                 '^Defaults.*requiretty', use_sudo=True)


def disable_requiretty_on_sshd_config():
    """ allow sudo calls through ssh without a tty """
    log_green('disabling requiretty on sshd_config')
    comment_line('/etc/ssh/sshd_config',
                 '^Defaults.*requiretty', use_sudo=True)


def disable_selinux():
    """ disables selinux """

    if contains(filename='/etc/selinux/config',
                text='SELINUX=enforcing'):
        sed('/etc/selinux/config',
            'SELINUX=enforcing', 'SELINUX=disabled', use_sudo=True)

    if contains(filename='/etc/selinux/config',
                text='SELINUX=permissive'):
        sed('/etc/selinux/config',
            'SELINUX=permissive', 'SELINUX=disabled', use_sudo=True)

    if sudo('getenforce').lower() != 'disabled':
        with settings(warn_only=True, capture=True):
            sudo('/sbin/reboot')
        sleep_for_one_minute()


def does_container_exist(container):
    with settings(warn_only=True):
        result = sudo('docker inspect %s' % container)
        print('*********************************************')
        log_red(result.return_code)
    if result.return_code is 0:
        return True
    else:
        return False


def destroy(cloud, region, instance_id, access_key_id, secret_access_key):
    if cloud == 'ec2':
        destroy_ec2(region, instance_id, access_key_id, secret_access_key)
    if cloud == 'rackspace':
        destroy_rackspace(region, instance_id, access_key_id, secret_access_key)


def destroy_ebs_volume(region, volume_id, access_key_id, secret_access_key):
    """ destroys an ebs volume """
    conn = connect_to_ec2(region, access_key_id, secret_access_key)

    if ebs_volume_exists(region, volume_id, access_key_id, secret_access_key):
        log_yellow('destroying EBS volume ...')
        conn.delete_volume(volume_id)


def destroy_ec2(region, instance_id, access_key_id, secret_access_key):
    """ terminates the instance """
    conn = connect_to_ec2(region, access_key_id, secret_access_key)

    data = get_ec2_info(instance_id=instance_id,
                        region=region,
                        access_key_id=access_key_id,
                        secret_access_key=secret_access_key,
                        username=None)

    instance = conn.terminate_instances(instance_ids=[data['id']])[0]
    log_yellow('destroying instance ...')
    while instance.state != "terminated":
        log_yellow("Instance state: %s" % instance.state)
        sleep(10)
        instance.update()
    volume_id = data['volume']
    if volume_id:
        destroy_ebs_volume(region, volume_id, access_key_id,
                           secret_access_key)
    os.unlink('data.json')


def destroy_rackspace(region, instance_id, access_key_id, secret_access_key):
    """ terminates the instance """
    nova = connect_to_rackspace(region,
                                access_key_id,
                                secret_access_key)

    server = nova.servers.get(instance_id)
    log_yellow('deleting rackspace instance ...')
    server.delete()

    # wait for server to be deleted
    try:
        while True:
            server = nova.servers.get(server.id)
            log_yellow('waiting for deletion ...')
            sleep(5)
    except:
        pass
    log_green('The server has been deleted')
    os.unlink('data.json')


def does_image_exist(image):
    with settings(warn_only=True):
        result = sudo('docker images')
        if image in result:
            return True
        else:
            return False


def down(cloud, instance_id, region, access_key_id, secret_access_key):
    halt(cloud, instance_id, region, access_key_id, secret_access_key)


def down_ec2(instance_id, region, access_key_id, secret_access_key):
    """ shutdown of an existing EC2 instance """
    conn = connect_to_ec2(region, access_key_id, secret_access_key)
    # get the instance_id from the state file, and stop the instance
    instance = conn.stop_instances(instance_ids=instance_id)[0]
    while instance.state != "stopped":
        log_yellow("Instance state: %s" % instance.state)
        sleep(10)
        instance.update()
    log_green('Instance state: %s' % instance.state)


def down_rackspace(cloud,
                   instance_id,
                   region,
                   access_key_id,
                   secret_access_key):
    nova = connect_to_rackspace(region, access_key_id, secret_access_key)
    # halt the rackspace instance
    # this will destroy the instance
    server = nova.servers.get(instance_id)
    if server.status == "ACTIVE":
        with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                      warn_only=True, capture=True):
            sudo('/sbin/halt')

    while server.status == "ACTIVE":
        log_yellow("Instance state: %s" % server.status)
        sleep(10)
        server = nova.servers.get(instance_id)
    log_yellow("Instance state: %s" % server.status)


def ebs_volume_exists(region, volume_id, access_key_id, secret_access_key):
    """ finds out if a ebs volume exists """
    conn = connect_to_ec2(region, access_key_id, secret_access_key)
    for vol in conn.get_all_volumes():
        if vol.id == volume_id:
            return True


def ec2():
    env.cloud = 'ec2'


def enable_apt_repositories(prefix, url, version, repositories):
    """ adds an apt repository """
    with settings(hide('warnings', 'running', 'stdout'),
                  warn_only=False, capture=True):
        sudo('apt-add-repository "%s %s %s %s"' % (prefix,
                                                   url,
                                                   version,
                                                   repositories))
        sudo("apt-get update")


def enable_firewalld_service():
    """ install and enables the firewalld service """
    yum_install(packages=['firewalld'])
    systemd(service='firewalld', unmask=True)


def enable_marathon_basic_authentication(principal, password):
    """ configures marathon to start with authentication """
    upstart_file = '/etc/init/marathon.conf'
    with hide('running', 'stdout'):
        sudo('echo -n "{}" > /etc/marathon-mesos.credentials'.format(password))
    boot_args = ' '.join(['exec',
                          '/usr/bin/marathon',
                          '--http_credentials',
                          '"{}:{}"'.format(principal, password),
                          '--mesos_authentication_principal',
                          principal,
                          '--mesos_authentication_secret_file',
                          '/etc/marathon-mesos.credentials'])

    # check if the init conf file contains the exact user and password
    if not file_contains(upstart_file, boot_args, use_sudo=True):
        sed(upstart_file, 'exec /usr/bin/marathon.*', boot_args, use_sudo=True)
        file_attribs(upstart_file, mode=700, sudo=True)
        restart_service('marathon')


def enable_mesos_basic_authentication(principal, password):
    """ enables and adds a new authorized principal """
    restart = False
    secrets_file = '/etc/mesos/secrets'
    secrets_entry = '%s %s' % (principal, password)
    if not file_contains(secrets_file, secrets_entry, use_sudo=True):
        file_append(secrets_file, secrets_entry, use_sudo=True)
        file_attribs(secrets_file, mode=700, sudo=True)
        restart = True

    # set new startup parameters for mesos-master
    with cd('/etc/mesos-master'):
        if not file_contains('credentials',
                             secrets_file, use_sudo=True):
            sudo('echo %s > credentials' % secrets_file)
            restart = True

        if not exists('?authenticate', use_sudo=True):
            sudo('touch \?authenticate')
            file_attribs('?authenticate', mode=700, sudo=True)
            restart = True

    if restart:
        restart_service('mesos-master')


def enable_selinux():
    """ disables selinux """

    if not contains(filename='/etc/selinux/config',
                    text='SELINUX=enforcing'):
        sed('/etc/selinux/config',
            'SELINUX=.*', 'SELINUX=enforcing', use_sudo=True)

    if contains(filename='/etc/selinux/config',
                text='SELINUXTYPE=targeted'):
        sed('/etc/selinux/config',
            'SELINUXTYPE=.*', 'SELINUX=targeted', use_sudo=True)

    sudo('/sbin/setenforce 1')

    if sudo('getenforce') != 'Enforcing':
        with settings(warn_only=True, capture=True):
            sudo('/sbin/reboot')
        sleep_for_one_minute()


def file_attribs(location, mode=None, owner=None, group=None, sudo=False):
    """Updates the mode/owner/group for the remote file at the given
    location."""
    return dir_attribs(location, mode, owner, group, False, sudo)


def get_container_id(container):
        with hide('running', 'stdout'):
            result = sudo(
                "docker ps -a | grep %s | awk '{print $1}'" % container)
            return result


def get_ec2_info(instance_id,
                 region,
                 access_key_id,
                 secret_access_key,
                 username):
    """ queries EC2 for details about a particular instance_id
    """
    conn = connect_to_ec2(region, access_key_id, secret_access_key)
    instance = conn.get_only_instances(
        filters={'instance_id': instance_id}
        )[0]

    data = {}
    data['public_dns_name'] = instance.public_dns_name
    data['id'] = instance.id
    data['instance_type'] = instance.instance_type
    data['ip_address'] = instance.ip_address
    data['architecture'] = instance.architecture
    data['state'] = instance.state
    data['region'] = region
    data['cloud_type'] = 'ec2'
    data['username'] = username

    # find out the distribution running on the instance
    if username is not None:
        wait_for_ssh(data['ip_address'])
        with settings(host_string=username + '@' + data['ip_address']):
            data['distribution'] = linux_distribution(username,
                                                      data['ip_address'])
            data['os_release'] = os_release(username,
                                            data['ip_address'])

    try:
        volume = conn.get_all_volumes(
            filters={'attachment.instance-id': instance.id})[0].id
        data['volume'] = volume
    except:
        data['volume'] = ''
    return data


def get_image_id(image):
        result = sudo("docker images | grep %s | awk '{print $3}'" % image)
        return result


def get_ip_address_from_rackspace_server(server_id):
    """
    returns an ipaddress for a rackspace instance
    """
    nova = connect_to_rackspace()
    server = nova.servers.get(server_id)
    # the server was assigned IPv4 and IPv6 addresses, locate the IPv4 address
    ip_address = None
    for network in server.networks['public']:
        if re.match('\d+\.\d+\.\d+\.\d+', network):
            ip_address = network
            break

    # find out if we have an ip address
    if ip_address is None:
        log_red('No IP address assigned')
        return False
    else:
        return ip_address


def get_rackspace_info(server_id,
                       region,
                       access_key_id,
                       secret_access_key,
                       username):
    """ queries Rackspace for details about a particular server id
    """
    nova = connect_to_rackspace(region, access_key_id, secret_access_key)
    server = nova.servers.get(server_id)

    data = {}
    data['id'] = server.id
    # this needs to be tackled
    data['ip_address'] = server.accessIPv4
    data['state'] = server.status
    data['region'] = region
    data['cloud_type'] = 'rackspace'
    data['username'] = username

    # find out the distribution running on the instance
    if username is not None:
        wait_for_ssh(data['ip_address'])
        with settings(host_string=username + '@' + data['ip_address']):
            data['distribution'] = linux_distribution(username,
                                                      data['ip_address'])
            data['os_release'] = os_release(username,
                                            data['ip_address'])

    data['volume'] = ''
    return data


def git_clone(repo_url, repo_name):
    """ clones a git repository """
    if not exists(repo_name):
        run("git clone %s" % repo_url)


def halt(cloud, instance_id, region, access_key_id, secret_access_key):
    if cloud == 'ec2':
        down_ec2(instance_id, region, access_key_id, secret_access_key)
    if cloud == 'rackspace':
        down_rackspace(instance_id, region, access_key_id, secret_access_key)


def install_centos_development_tools():
    """ installs development tools """
    yum_group_install(groups=['Development tools'])


def install_docker():
    """ installs docker """
    with settings(hide('running', 'stdout')):
        run('curl https://get.docker.com/ > /tmp/install-docker.sh')
        sudo('sh /tmp/install-docker.sh')
        systemd('docker.service')


def install_oracle_java(distribution, java_version):
    """ installs oracle java """
    if 'ubuntu' in distribution:
        accept_oracle_license = ('echo '
                                 'oracle-java' + java_version + 'installer '
                                 'shared/accepted-oracle-license-v1-1 '
                                 'select true | '
                                 '/usr/bin/debconf-set-selections')
        with settings(hide('running', 'stdout')):
            sudo(accept_oracle_license)

        with settings(hide('running', 'stdout'),
                      prompts={"Press [ENTER] to continue or ctrl-c to cancel adding it": "yes"}): # noqa
            sudo("yes | add-apt-repository ppa:webupd8team/java")

        with settings(hide('running', 'stdout')):
            install_os_updates(distribution)
            apt_install(packages=['oracle-java8-installer',
                                  'oracle-java8-set-default'])


def install_mesos_single_box_mode(distribution):
    """ install mesos (all of it) on a single node"""

    if 'ubuntu' in distribution:
        log_green('adding mesosphere apt-key')
        apt_add_key(keyid='E56151BF')

        os = lsb_release()
        apt_string = 'deb http://repos.mesosphere.io/%s %s main' % (
            os['DISTRIB_ID'], os['DISTRIB_CODENAME'])

        log_green('adding mesosphere apt repository')
        apt_add_repository_from_apt_string(apt_string, 'mesosphere.list')

        log_green('installing ubuntu development tools')
        install_ubuntu_development_tools()

        install_oracle_java(distribution, '8')

        log_green('installing mesos and marathon')
        apt_install(packages=['mesos', 'marathon'])

        if not file_contains('/etc/default/mesos-master',
                             'MESOS_QUORUM=1', use_sudo=True):
            file_append('/etc/default/mesos-master',
                        'MESOS_QUORUM=1', use_sudo=True)

            log_green('restarting services...')
            for svc in ['zookeeper', 'mesos-master', 'mesos-slave', 'marathon']:
                restart_service(svc)

        if not file_contains('/etc/mesos-slave/work_dir',
                             '/data/mesos', use_sudo=True):
            file_append('/etc/mesos-slave/work_dir',
                        '/data/mesos', use_sudo=True)

            log_green('restarting services...')
            for svc in ['mesos-slave']:
                restart_service(svc)

        log_green('enabling nginx autoindex on /...')
        insert_line_in_file_after_regex(
            path='/etc/nginx/sites-available/default',
            line='                autoindex on;',
            after_regex='^[^#]*location \/ {',
            use_sudo=True)
        log_green('restarting nginx')
        restart_service('nginx')


def insert_line_in_file_after_regex(path, line, after_regex, use_sudo=False):
    """ inserts a line in the middle of a file """

    tmpfile = str(uuid.uuid4())
    get_file(path, tmpfile, use_sudo=use_sudo)
    with open(tmpfile) as f:
        original = f.read()

    if line not in original:
        outfile = str(uuid.uuid4())
        with open(outfile, 'w') as output:
            for l in original.split('\n'):
                output.write(l + '\n')
                if re.match(after_regex, l) is not None:
                    output.write(line + '\n')

        upload_file(local_path=outfile,
                    remote_path=path,
                    use_sudo=use_sudo)
        os.unlink(outfile)
    os.unlink(tmpfile)


def install_gem(gem):
    """ install a particular gem """
    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=False, capture=True):
        run("gem install %s --no-rdoc --no-ri" % gem)


def install_recent_git_from_source():
    # update git
    sudo("wget -c https://www.kernel.org/pub/software/scm/git/git-2.4.6.tar.gz")
    sudo("test -e git-2.4.6 || tar -zxf git-2.4.6.tar.gz")
    with cd('git-2.4.6'):
        sudo('test -e /usr/local/bin/git || ./configure --prefix=/usr/local')
        sudo('test -e /usr/local/bin/git || make')
        sudo('test -e /usr/local/bin/git || make install')


def install_os_updates(distribution, force=False):
    """ installs OS updates """
    if ('centos' in distribution or
            'rhel' in distribution or
            'redhat' in distribution):
        log_green('installing OS updates')
        sudo("yum -y --quiet clean all")
        sudo("yum group mark convert")
        sudo("yum -y --quiet update")

    if ('ubuntu' in distribution or
            'debian' in distribution):
        with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                      warn_only=False, capture=True):
            sudo("DEBIAN_FRONTEND=noninteractive apt-get update")
            if force:
                sudo("sudo DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' upgrade --force-yes")
            else:
                sudo("sudo DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' upgrade")


def install_python_module(name):
    """ instals a python module using pip """

    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=False, capture=True):
        run('pip --quiet install %s' % name)


def install_python_module_locally(name):
    """ instals a python module using pip """
    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=False, capture=True):
        local('pip --quiet install %s' % name)


def install_system_gem(gem):
    """ install a particular gem """
    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=False, capture=True):
        sudo("gem install %s --no-rdoc --no-ri" % gem)


def install_ubuntu_development_tools():
    """ installs development tools """
    apt_install(packages=['build-essential'])


def install_zfs_from_testing_repository():
    # Enable debugging for ZFS modules
    sudo("echo SPL_DKMS_DISABLE_STRIP=y >> /etc/sysconfig/spl")
    sudo("echo ZFS_DKMS_DISABLE_STRIP=y >> /etc/sysconfig/zfs")
    sudo("yum install --quiet -y --enablerepo=zfs-testing zfs")
    sudo("dkms autoinstall")
    sudo("modprobe zfs")


def install_virtualbox(distribution, force_setup=False):
    """ install virtualbox """

    if 'ubuntu' in distribution:
        with hide('running', 'stdout'):
            sudo('apt-get update')
            sudo('apt-get -y upgrade')
            install_ubuntu_development_tools()
            apt_install(packages=['dkms',
                                  'linux-headers-generic',
                                  'build-essential'])
            sudo('wget -q '
                 'https://www.virtualbox.org/download/oracle_vbox.asc -O- |'
                 'sudo apt-key add -')

            os = lsb_release()
            apt_string = ' '.join(
                ['deb',
                 'http://download.virtualbox.org/virtualbox/debian',
                 '%s contrib' % os['DISTRIB_CODENAME']])

            apt_add_repository_from_apt_string(apt_string, 'vbox.list')

            apt_install(packages=['virtualbox-5.0'])

            loaded_modules = sudo('lsmod')

            if 'vboxdrv' not in loaded_modules or force_setup:
                sudo('/etc/init.d/vboxdrv setup')

            sudo('wget -c '
                 'http://download.virtualbox.org/virtualbox/5.0.4/'
                 'Oracle_VM_VirtualBox_Extension_Pack-5.0.4-102546.vbox-extpack') # noqa

            sudo('VBoxManage extpack install --replace '
                 'Oracle_VM_VirtualBox_Extension_Pack-5.0.4-102546.vbox-extpack') # noqa


def install_vagrant(distribution, version):
    """ install vagrant """

    if 'ubuntu' in distribution:
        apt_install_from_url('vagrant',
                             'https://dl.bintray.com/mitchellh/vagrant/'
                             'vagrant_%s_x86_64.deb' % version)


def install_vagrant_plugin(plugin, use_sudo=False):
    """ install vagrant plugin """

    cmd = 'vagrant plugin install %s' % plugin

    with settings(hide('running', 'stdout')):
        if use_sudo:
            if plugin not in sudo('vagrant plugin list'):
                sudo(cmd)
        else:
            if plugin not in run('vagrant plugin list'):
                run(cmd)


def is_vagrant_plugin_installed(plugin, use_sudo=False):
    """ checks if vagrant plugin is installed """

    cmd = 'vagrant plugin list'

    if use_sudo:
        results = sudo(cmd)
    else:
        results = run(cmd)

    installed_plugins = []
    for line in results:
        plugin = re.search('^(\S.*) \((.*)\)$', line)
        installed_plugins.append({'name': plugin.group(0),
                                  'version': plugin.group(1)})
        return installed_plugins


def is_deb_package_installed(pkg):
    """ checks if a particular deb package is installed """

    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=True, capture=True):

        result = sudo('dpkg-query -l "%s" | grep -q ^.i' % pkg)
        return not bool(result.return_code)


def is_package_installed(distribution, pkg):
    """ checks if a particular package is installed """
    if ('centos' in distribution or
            'el' in distribution or
            'redhat' in distribution):
        return(is_rpm_package_installed(pkg))

    if ('ubuntu' in distribution or
            'debian' in distribution):
        return(is_deb_package_installed(pkg))


def is_rpm_package_installed(pkg):
    """ checks if a particular rpm package is installed """

    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=True, capture=True):

        result = sudo("rpm -q %s" % pkg)
        if result.return_code == 0:
            return True
        elif result.return_code == 1:
            return False
        else:   # print error to user
            print(result)
            raise SystemExit()


def is_there_state():
    """ checks is there is valid state available on disk """
    if os.path.isfile('data.json'):
        return True
    else:
        return False


def is_ssh_available(host, port=22):
    """ checks if ssh port is open """
    s = socket.socket()
    try:
        s.connect((host, port))
        return True
    except:
        return False


def os_release(username, ip_address):
    """ returns /etc/os-release in a dictionary """
    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=True, capture=True):

        _os_release = {}
        with settings(host_string=username + '@' + ip_address):
            data = run('cat /etc/os-release')
        for line in data.split('\n'):
            if not line:
                continue
            parts = line.split('=')
            if len(parts) == 2:
                _os_release[parts[0]] = parts[1].strip('\n\r"')

        return _os_release


def linux_distribution(username, ip_address):
    """ returns the linux distribution in lower case """
    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=True, capture=True):
        data = os_release(username, ip_address)
        return(data['ID'])


def load_state_from_disk():
    """ loads the state from a loca data.json file
    """
    if is_there_state():
        with open('data.json', 'r') as f:
            data = json.load(f)
        return data
    else:
        return False


def log_green(msg):
    print(green(msg))


def log_yellow(msg):
    print(yellow(msg))


def log_red(msg):
    print(red(msg))


def lsb_release():
    """ returns /etc/lsb-release in a dictionary """
    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=True, capture=True):

        _lsb_release = {}
        data = run('cat /etc/lsb-release')
        for line in data.split('\n'):
            if not line:
                continue
            parts = line.split('=')
            if len(parts) == 2:
                _lsb_release[parts[0]] = parts[1].strip('\n\r"')

        return _lsb_release


def print_ec2_info(region,
                   instance_id,
                   access_key_id,
                   secret_access_key,
                   username):
    """ outputs information about our EC2 instance """
    data = get_ec2_info(instance_id=instance_id,
                        region=region,
                        access_key_id=access_key_id,
                        secret_access_key=secret_access_key,
                        username=username)

    log_green("region: %s" % data['region'])
    log_green("Instance_type: %s" % data['instance_type'])
    log_green("Instance state: %s" % data['state'])
    log_green("Public dns: %s" % data['public_dns_name'])
    log_green("Ip address: %s" % data['ip_address'])
    log_green("volume: %s" % data['volume'])
    log_green("user: %s" % data['username'])
    log_green("ssh -i %s %s@%s" % (env.key_filename,
                                   username,
                                   data['ip_address']))


def print_rackspace_info(region,
                         instance_id,
                         access_key_id,
                         secret_access_key,
                         username):
    """ outputs information about our Rackspace instance """
    data = get_rackspace_info(server_id=instance_id,
                              region=region,
                              access_key_id=access_key_id,
                              secret_access_key=secret_access_key,
                              username=username)

    log_green("region: %s" % data['region'])
    log_green("Instance state: %s" % data['state'])
    log_green("Ip address: %s" % data['ip_address'])
    log_green("volume: %s" % data['volume'])
    log_green("user: %s" % data['username'])
    log_green("ssh -i %s %s@%s" % (env.key_filename,
                                   username,
                                   data['ip_address']))


def rackspace():
    env.cloud = 'rackspace'
    env.user = 'root'


def reboot():
    with settings(warn_only=True, capture=True):
        sudo('shutdown -r now')
        sleep_for_one_minute()


def remove_image(image):
    sudo('docker rmi -f %s' % get_image_id(image))


def remove_container(container):
    sudo('docker rm -f %s' % get_container_id(container))


def restart_service(service):
    """ restarts a service  """
    with settings(hide('running', 'stdout'), warn_only=True):
        log_yellow('stoping service %s' % service)
        sudo('service %s stop' % service)
        log_yellow('starting service %s' % service)
        sudo('service %s start' % service)


def rsync():
    """ syncs the src code to the remote box """
    log_green('syncing code to remote box...')
    data = load_state_from_disk()
    if 'SOURCE_PATH' in os.environ:
        with lcd(os.environ['SOURCE_PATH']):
            local("rsync  -a "
                  "--info=progress2 "
                  "--exclude .git "
                  "--exclude .tox "
                  "--exclude .vagrant "
                  "--exclude venv "
                  ". "
                  "-e 'ssh -C -i " + env.ec2_key_filename + "' "
                  "%s@%s:" % (env.user, data['ip_address']))
    else:
        print('please export SOURCE_PATH before running rsync')
        exit(1)


def save_state_locally(cloud,
                       instance_id,
                       region,
                       username,
                       access_key_id,
                       secret_access_key):
    """ queries EC2 for details about a particular instance_id and
        stores those details locally
    """
    if cloud == 'ec2':
        # retrieve the IP information from the instance
        data = get_ec2_info(instance_id,
                            region,
                            access_key_id,
                            secret_access_key,
                            username)
    if cloud == 'rackspace':
        # retrieve the IP information from the instance
        data = get_rackspace_info(instance_id,
                                  region,
                                  access_key_id,
                                  secret_access_key,
                                  username)
        data['cloud_type'] = 'rackspace'

    # dump it all
    with open('data.json', 'w') as f:
        json.dump(data, f)


def sleep_for_one_minute():
    sleep(60)


def ssh_session(key_filename,
                username,
                ip_address,
                *cli):
    """ opens a ssh shell to the host """
    local('ssh -t -i %s %s@%s %s' % (key_filename,
                                     username,
                                     ip_address,
                                     "".join(chain.from_iterable(cli))))


def status(cloud,
           region,
           instance_id,
           access_key_id,
           secret_access_key,
           username):

    if cloud == 'ec2':
        print_ec2_info(region,
                       instance_id,
                       access_key_id,
                       secret_access_key,
                       username)

    if cloud == 'rackspace':
        print_rackspace_info(region,
                             instance_id,
                             access_key_id,
                             secret_access_key,
                             username)


def systemd(service, start=True, enabled=True, unmask=False, restart=False):
    """ manipulates systemd services """

    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=True, capture=True):

        if restart:
            sudo('systemctl restart %s' % service)
        else:
            if start:
                sudo('systemctl start %s' % service)
            else:
                sudo('systemctl stop %s' % service)

        if enabled:
            sudo('systemctl enable %s' % service)
        else:
            sudo('systemctl disable %s' % service)

        if unmask:
            sudo('systemctl unmask %s' % service)


def terminate():
    destroy()


def up(cloud, instance_id, region, access_key_id, secret_access_key, username):
    if cloud == 'ec2':
        up_ec2(region, access_key_id, secret_access_key, instance_id, username)
    if cloud == 'rackspace':
        up_rackspace(region,
                     access_key_id,
                     secret_access_key,
                     instance_id,
                     username)


def up_ec2(region,
           access_key_id,
           secret_access_key,
           instance_id,
           username):
    """ boots an existing ec2_instance """

    conn = connect_to_ec2(region, access_key_id, secret_access_key)
    # boot the ec2 instance
    instance = conn.start_instances(instance_ids=instance_id)[0]
    while instance.state != "running":
        log_yellow("Instance state: %s" % instance.state)
        sleep(10)
        instance.update()
    # the ip_address has changed so we need to get the latest data from ec2
    data = get_ec2_info(instance_id=instance_id,
                        region=region,
                        access_key_id=access_key_id,
                        secret_access_key=secret_access_key,
                        username=username)
    # and make sure we don't return until the instance is fully up
    wait_for_ssh(data['ip_address'])
    # lets update our local state file with the new ip_address
    save_state_locally(cloud='ec2',
                       instance_id=instance_id,
                       region=region,
                       username=username,
                       access_key_id=access_key_id,
                       secret_access_key=secret_access_key)

    env.hosts = data['ip_address']

    print_ec2_info(region,
                   instance_id,
                   access_key_id,
                   secret_access_key,
                   username)


def up_rackspace(region,
                 access_key_id,
                 secret_access_key,
                 instance_id,
                 username):
    """ boots an existing rackspace instance, or creates a new one if needed """
    # if we don't have a state file, then its likely we need to create a new
    # rackspace instance.
    log_red('not implemented')
    exit(1)


def update_system_pip_to_latest_pip():
    """ install the latest pip """
    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=False, capture=True):
        sudo("pip install --quiet --upgrade pip")


def update_to_latest_pip():
    """ install the latest pip """
    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=False, capture=True):
        run("pip install --quiet --upgrade pip")


def yum_install(**kwargs):
    """
        installs a yum package
    """
    if 'repo' in kwargs:
        repo = kwargs['repo']

    for pkg in list(kwargs['packages']):
        if is_package_installed(distribution='el', pkg=pkg) is False:
            if 'repo' in locals():
                log_green("installing %s from repo %s ..." % (pkg, repo))
                sudo("yum install -y --quiet --enablerepo=%s %s" % (repo, pkg))
            else:
                log_green("installing %s ..." % pkg)
                sudo("yum install -y --quiet %s" % pkg)


def yum_group_install(**kwargs):
    """ instals a yum group """
    for grp in list(kwargs['groups']):
        log_green("installing %s ..." % grp)
        if 'repo' in kwargs:
            repo = kwargs['repo']
            sudo("yum groupinstall -y --quiet "
                 "--enablerepo=%s '%s'" % (repo, grp))
        else:
            sudo("yum groups mark install -y --quiet '%s'" % grp)
            sudo("yum groups mark convert -y --quiet '%s'" % grp)
            sudo("yum groupinstall -y --quiet '%s'" % grp)


def yum_install_from_url(pkg_name, url):
    """ installs a pkg from a url
        p pkg_name: the name of the package to install
        p url: the full URL for the rpm package
    """
    if is_package_installed(distribution='el', pkg=pkg_name) is False:
        log_green("installing %s from %s" % (pkg_name, url))
        with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                      warn_only=True, capture=True):

            result = sudo("rpm -i %s" % url)
            if result.return_code == 0:
                return True
            elif result.return_code == 1:
                return False
            else:  # print error to user
                print(result)
                raise SystemExit()


def wait_for_ssh(host, port=22, timeout=600):
    """ probes the ssh port and waits until it is available """
    log_yellow('waiting for ssh...')
    for iteration in xrange(1, timeout): #noqa
        sleep(1)
        if is_ssh_available(host, port):
            return True
        else:
            log_yellow('waiting for ssh...')
