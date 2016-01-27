# vim: ai ts=4 sts=4 et sw=4 ft=python fdm=indent et foldlevel=0

from fabric.api import sudo, settings
from fabric.context_managers import hide
from bookshelf.api_v2.os_helpers import install_os_updates
from bookshelf.api_v2.pkg import apt_install


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
