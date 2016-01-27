# vim: ai ts=4 sts=4 et sw=4 ft=python fdm=indent et foldlevel=0

import pyrax
import re
import sys
from fabric.api import env
from sys import exit
from time import sleep
from bookshelf.api_v2.logging_helpers import log_green, log_yellow, log_red
from bookshelf.api_v2.time_helpers import sleep_for_one_minute
from bookshelf.api_v2.cloud import wait_for_ssh


def connect_to_rackspace(region,
                         access_key_id,
                         secret_access_key):
    """ returns a connection object to Rackspace  """
    pyrax.set_setting('identity_type', 'rackspace')
    pyrax.set_default_region(region)
    pyrax.set_credentials(access_key_id, secret_access_key)
    nova = pyrax.connect_to_cloudservers(region=region)
    return nova


def create_rackspace_image(connection,
                           server_id,
                           name,
                           description,
                           block_device_mapping=None):

    image_id = connection.servers.create_image(server_id, name)
    image = connection.images.get(image_id).status.lower()
    log_green('creating rackspace image...')
    while connection.images.get(image_id).status.lower() not in ['active',
                                                                 'error']:
        log_green('building rackspace image...')
        sleep_for_one_minute()

    if image == 'error':
        log_red('error creating image')
        sys.exit(1)

    log_green('finished image: %s' % image_id)
    return image_id


def create_server_rackspace(connection,
                            distribution,
                            disk_name,
                            disk_size,
                            ami,
                            region,
                            key_pair,
                            instance_type,
                            instance_name,
                            tags={},
                            security_groups=None):
    """
    Creates Rackspace Instance and saves it state in a local json file
    """

    log_yellow("Creating Rackspace instance...")

    flavor = connection.flavors.find(name=instance_type)
    image = connection.images.find(name=ami)

    server = connection.servers.create(name=instance_name,
                                       flavor=flavor.id,
                                       image=image.id,
                                       region=region,
                                       availability_zone=region,
                                       key_name=key_pair)

    while server.status == 'BUILD':
        log_yellow("Waiting for build to finish...")
        sleep(5)
        server = connection.servers.get(server.id)

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
    return server


def destroy_rackspace(connection, region, instance_id):
    """ terminates the instance """

    server = connection.servers.get(instance_id)
    log_yellow('deleting rackspace instance ...')
    server.delete()

    # wait for server to be deleted
    try:
        while True:
            server = connection.servers.get(server.id)
            log_yellow('waiting for deletion ...')
            sleep(5)
    except:
        pass
    log_green('The server has been deleted')


def down_rackspace(connection, region, instance_id):
    """ terminates the instance """

    return(
        destroy_rackspace(connection, region, instance_id)
    )


def get_ip_address_from_rackspace_server(connection, server_id):
    """
    returns an ipaddress for a rackspace instance
    """
    server = connection.servers.get(server_id)
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


def get_rackspace_info(connection,
                       server_id):
    """ queries Rackspace for details about a particular server id
    """
    server = connection.servers.get(server_id)

    data = {}
    data['ip_address'] = server.accessIPv4
    data['accessIPv4'] = server.accessIPv4
    data['accessIPv6'] = server.accessIPv6
    data['addresses'] = server.addresses
    data['created'] = server.created
    data['flavor'] = server.flavor
    data['id'] = server.hostId
    data['human_id'] = server.human_id
    data['image'] = server.image['id']
    data['key_name'] = server.key_name
    data['state'] = server.status
    data['metadata'] = server.metadata
    data['name'] = server.name
    data['networks'] = server.networks
    data['tenant_id'] = server.tenant_id
    data['user_id'] = server.user_id
    data['cloud_type'] = 'rackspace'
    return data


def rackspace():
    env.cloud = 'rackspace'
    env.user = 'root'


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
