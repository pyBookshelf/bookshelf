import os
from fabric.api import local, env
from fabric.context_managers import settings, quiet, show, hide


def with_ephemeral_container(images=None, verbose=False, privileged=False):
    """
    A decorator that creates ephemeral docker containers, executes the
    wrapped function and destroys the docker container.

    takes a list of docker images, and executes the wrapped function for each
    one of those images.

    params:
        list images: array containing a list of docker images
        bool verbose: print out debug information
        bool privileged: run the docker instance in privileged mode
    """

    if not images:
        images = []

    def decorator(func):
        def wrapper(*args, **kwargs):
            # iterates and executes the wrapped function/testcase
            # for each one of the docker images.
            # ex: centos, ubuntu-vivid, ubuntu-trusty
            for image in images:
                c1 = docker_run(image=image, privileged=privileged)
                hs = build_host_string(c1, env.docker_host)

                # set some fabric settings to either be very verbose
                # or very quiet.
                if verbose:
                    fabric_flags = show('debug')
                else:
                    fabric_flags = hide('everything')

                with settings(fabric_flags, host_string=hs):
                    try:
                        print("In method: %s for docker image %s" % (
                            func.func_name, image))
                        func(*args, **kwargs)
                        docker_rm(c1)
                    except:
                        docker_rm(c1)
                        raise
        return wrapper
    return decorator


def build_docker_image(image, base_image, distribution):
    """
    Builds a docker image that will be used in the different TestCases

    params:
        string image: tag of the new docker image to produce
        string base_image: name of the base docker image (centos, ...)
        string distribution: which distribution to build (centos/ubuntu)
    """

    if 'ubuntu' in distribution:
        contents = [
            'FROM ' + base_image,
            'RUN echo "nameserver 8.8.8.8 > /etc/resolv.conf"',
            'RUN apt-get update && apt-get install -y sudo openssh-server lsb-release software-properties-common python-pip curl',  # noqa
            'RUN cd /usr/local/bin && wget -c https://raw.githubusercontent.com/jpetazzo/dind/master/wrapdocker',
            'RUN chmod 755 /usr/local/bin/wrapdocker'
        ]
    if 'centos' in distribution:
        contents = [
            'FROM ' + base_image,
            'RUN echo "nameserver 8.8.8.8 > /etc/resolv.conf"',
            # fix for: https://bugzilla.redhat.com/show_bug.cgi?id=1213602#c13
            'RUN yum clean all',
            'RUN touch /var/lib/rpm/*',
            'RUN yum install --disableplugin=fastestmirror -y yum-utils',
            'RUN yum install --disableplugin=fastestmirror -y openssh-server',
            'RUN ssh-keygen -b 1024 -t rsa -f /etc/ssh/ssh_host_key',
            'RUN ssh-keygen -b 1024 -t rsa -f /etc/ssh/ssh_host_rsa_key',  # noqa
            'RUN ssh-keygen -b 1024 -t dsa -f /etc/ssh/ssh_host_dsa_key',  # noqa
            'RUN yum install --disableplugin=fastestmirror -y yum-utils',
            'RUN yum install --disableplugin=fastestmirror -y sudo',
            'RUN yum install --disableplugin=fastestmirror -y openssh-server',
            'RUN yum install --disableplugin=fastestmirror -y rubygems',
            'RUN yum install --disableplugin=fastestmirror -y python-devel',
            'RUN yum install --disableplugin=fastestmirror -y curl',
            'RUN yum install --disableplugin=fastestmirror -y wget',
            'RUN curl "https://bootstrap.pypa.io/get-pip.py" -o "get-pip.py"',
            'RUN cd /usr/local/bin && wget -c https://raw.githubusercontent.com/jpetazzo/dind/master/wrapdocker',
            'RUN chmod 755 /usr/local/bin/wrapdocker',
            'RUN python get-pip.py'
        ]

    contents = contents + [
        'RUN mkdir /var/run/sshd',
        'RUN echo "root:root" | chpasswd',
        'RUN sed -i "s/PermitRootLogin without-password/PermitRootLogin yes/" /etc/ssh/sshd_config',  # noqa
        'RUN sed "s@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g" -i /etc/pam.d/sshd',  # noqa
        'ENV NOTVISIBLE "in users profile"',
        'RUN echo "export VISIBLE=now" >> /etc/profile',
        'RUN echo "nameserver 8.8.8.8" > /etc/resolv.conf',
        'EXPOSE 22',
        'CMD ["/usr/sbin/sshd", "-D"]'
    ]

    dockerfile = 'Dockerfile.' + distribution
    with open(dockerfile, 'w') as f:
        f.write('\n'.join(contents))

    local('docker build -f %s -t %s .' % (dockerfile, image),
          capture=False)


def docker_run(image, privileged=False):
    """
        runs a docker container

        params:
            string image: name of the docker image
            bool privileged: use docker --privileged flag
        returns:
            string: stdout of the docker run
    """

    flags = ''
    if privileged:
        flags = '--privileged'

    container = local(
        'docker run %s -d -P %s' % (flags, image), capture=True)
    return container


def docker_rm(container):
    """
        removes a docker container

        params:
            string container: docker id of the container to remove
    """
    with settings(quiet()):
        local('docker rm --force %s' % container)


def docker_container_port(container):
    """
        returns the ssh port number for a docker instance

        params:
            string container: docker container id

        returns:
            string: port number
    """
    with settings(quiet()):
        output = local(
            'docker port %s 22' % container,
            capture=True
        )

        return output.split(':')[1]


def docker_ip(docker_host_string):
    """
        returns the ip address of the docker daemon

        params:
            string docker_host_string: URL of the docker daemon
        returns:
            string: ip address of the docker host
    """
    return docker_host_string.split(':')[1].split('//')[1]


def build_host_string(container, docker_host_string):
    """
        builds a fabric ssh host string for a docker container

        params:
            string container: docker instance id
            string docker_host_string: URL for the docker daemon

        returns:
            string: < root@docker_ip_address:port_number >
    """
    ip = docker_ip(docker_host_string)
    host_string = "root@%s:%s" % (ip,
                                  docker_container_port(container))
    return host_string


def prepare_required_docker_images():
    """ setups the required docker instances and fabric settings """

    # before running any tests, we need to make sure we have all the images we
    # require in our tests.

    # dict containing the name of the docker images to build,
    # the base docker image, and linux distro for that image.
    images = [
        {'image': 'ubuntu-trusty-ruby-ssh',
            'base_image': 'clusterhqci/fpm-ubuntu-trusty',
            'distribution': 'ubuntu-trusty'},

        {'image': 'ubuntu-vivid-ruby-ssh',
            'base_image': 'clusterhqci/fpm-ubuntu-vivid',
            'distribution': 'ubuntu-vivid'},

        {'image': 'centos-7-ruby-ssh',
            'base_image': 'centos:latest',
            'distribution': 'centos-7'}

    ]

    # set some fabric environ vars
    ip = local("docker run -it alpine route -n "
               "| grep -E '^0.0.0.0' | awk '{ print $2 }'", capture=True)

    env.docker_host = os.environ.get('DOCKER_HOST', 'http://%s:2376' % ip)
    env.password = 'root'
    env.user = 'root'

    # build the docker images we require to run the tests
    for item in images:
        if item['image'] not in local('docker images', capture=True):
            print('building docker image %s' % item['image'])
            build_docker_image(
                image=item['image'],
                base_image=item['base_image'],
                distribution=item['distribution']
            )
