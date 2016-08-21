# vim: ai ts=4 sts=4 et sw=4 ft=python fdm=indent et foldlevel=0

import re
from fabric.api import sudo, settings, run
from fabric.context_managers import hide
from bookshelf.api_v2.os_helpers import (install_ubuntu_development_tools,
                                         lsb_release)
from bookshelf.api_v2.pkg import (apt_add_repository_from_apt_string,
                                  apt_install_from_url,
                                  apt_install)


def install_virtualbox(distribution, force_setup=False):
    """ install virtualbox """

    if 'ubuntu' in distribution:
        with hide('running', 'stdout'):
            sudo('DEBIAN_FRONTEND=noninteractive apt-get update')
            sudo("sudo DEBIAN_FRONTEND=noninteractive apt-get -y -o "
                    "Dpkg::Options::='--force-confdef' "
                    "-o Dpkg::Options::='--force-confold' upgrade --force-yes")
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

                if 'Vivid Vervet' in run('cat /etc/os-release'):
                    sudo('systemctl start vboxdrv')
                else:
                    sudo('/etc/init.d/vboxdrv start')

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
    for line in results.split('\n'):

        if line:
            plugin = re.search('(.*)\s(.*)$', line)
            installed_plugins.append({'name': plugin.group(1),
                                      'version': plugin.group(2)})
            return installed_plugins
