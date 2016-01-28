# vim: ai ts=4 sts=4 et sw=4 ft=python fdm=indent et foldlevel=0

from fabric.api import sudo, settings, run
from fabric.context_managers import hide
from fabric.contrib.files import (
                                  contains)
from bookshelf.api_v2.logging_helpers import (log_green,
                                              log_red)
from bookshelf.api_v2.os_helpers import systemd


def cache_docker_image_locally(docker_image, log=False):
    if log:
        log_green('pulling docker image %s locally' % docker_image)
    sudo("docker pull %s" % docker_image)


def create_docker_group():
    """ creates the docker group """
    if not contains('/etc/group', 'docker', use_sudo=True):
        sudo("groupadd docker")


def does_container_exist(container):
    with settings(warn_only=True):
        result = sudo('docker inspect %s' % container)
        print('*********************************************')
        log_red(result.return_code)
    if result.return_code is 0:
        return True
    else:
        return False


def does_image_exist(image):
    with settings(warn_only=True):
        if image in sudo('docker images'):
            return True
        else:
            return False


def get_container_id(container):
        with hide('running', 'stdout'):
            result = sudo(
                "docker ps -a | grep %s | awk '{print $1}'" % container)
            return result


def get_image_id(image):
        result = sudo("docker images | grep %s | awk '{print $3}'" % image)
        return result


def install_docker():
    """ installs docker """
    with settings(hide('running', 'stdout')):
        run('curl https://get.docker.com/ > /tmp/install-docker.sh')
        sudo('sh /tmp/install-docker.sh')
        systemd('docker.service')


def remove_image(image):
    sudo('docker rmi -f %s' % get_image_id(image))


def remove_container(container):
    sudo('docker rm -f %s' % get_container_id(container))
