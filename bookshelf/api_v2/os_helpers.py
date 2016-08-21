# vim: ai ts=4 sts=4 et sw=4 ft=python fdm=indent et foldlevel=0

from fabric.api import sudo, settings, run
from fabric.context_managers import hide
from fabric.contrib.files import append as file_append
from fabric.contrib.files import comment as comment_line
from fabric.contrib.files import sed, contains

import bookshelf.api_v2 as bookshelf2


def add_usr_local_bin_to_path(log=False):
    """ adds /usr/local/bin to $PATH """
    if log:
        bookshelf2.logging_helpers.log_green('inserts /usr/local/bin into PATH')

    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  capture=True):
        try:
            sudo('echo "export PATH=/usr/local/bin:$PATH" '
                 '|sudo /usr/bin/tee /etc/profile.d/fix-path.sh')
            return True
        except:
            raise SystemExit(1)


def arch():
    """ returns the current cpu archictecture """
    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=True, capture=True):
        result = sudo('uname --machine').strip()
    return result


def dir_attribs(location, mode=None, owner=None,
                group=None, recursive=False, use_sudo=False):
    """ cuisine dir_attribs doesn't do sudo, so we implement our own
        Updates the mode/owner/group for the given remote directory."""
    args = ''
    if recursive:
        args = args + ' -R '

    if mode:
        if use_sudo:
            sudo('chmod %s %s %s' % (args, mode,  location))
        else:
            run('chmod %s %s %s' % (args, mode,  location))
    if owner:
        if use_sudo:
            sudo('chown %s %s %s' % (args, owner, location))
        else:
            run('chown %s %s %s' % (args, owner, location))
    if group:
        if use_sudo:
            sudo('chgrp %s %s %s' % (args, group, location))
        else:
            run('chgrp %s %s %s' % (args, group, location))
    return True


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
    return True


def dir_exists(location, use_sudo=False):
    """Tells if there is a remote directory at the given location."""
    with settings(hide('running', 'stdout', 'stderr'), warn_only=True):
        if use_sudo:
            # convert return code 0 to True
            return not bool(sudo('test -d %s' % (location)).return_code)
        else:
            return not bool(run('test -d %s' % (location)).return_code)


def disable_env_reset_on_sudo(log=False):
    """ updates /etc/sudoers so that users from %wheel keep their
        environment when executing a sudo call
    """
    if log:
        bookshelf2.logging_helpers.log_green('disabling env reset on sudo')

    file_append('/etc/sudoers',
                'Defaults:%wheel !env_reset,!secure_path',
                use_sudo=True,
                partial=True)
    return True


def disable_requiretty_on_sudoers(log=False):
    """ allow sudo calls through ssh without a tty """
    if log:
        bookshelf2.logging_helpers.log_green(
            'disabling requiretty on sudo calls')

    comment_line('/etc/sudoers',
                 '^Defaults.*requiretty', use_sudo=True)
    return True


def disable_requiretty_on_sshd_config(log=False):
    """ allow sudo calls through ssh without a tty """
    if log:
        bookshelf2.logging_helpers.log_green(
            'disabling requiretty on sshd_config')

    comment_line('/etc/ssh/sshd_config',
                 '^Defaults.*requiretty', use_sudo=True)
    return True


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
        bookshelf2.time_helpers.sleep_for_one_minute()


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
        bookshelf2.time_helpers.sleep_for_one_minute()


def file_attribs(location,
                 mode=None,
                 owner=None,
                 group=None,
                 use_sudo=False,
                 recursive=True):
    """Updates the mode/owner/group for the remote file at the given
    location."""
    return dir_attribs(location=location,
                       mode=mode,
                       owner=owner,
                       group=group,
                       recursive=recursive,
                       use_sudo=False)


def os_release():
    """ returns /etc/os-release in a dictionary """
    with settings(hide('warnings', 'running', 'stderr'),
                  warn_only=True, capture=True):

        release = {}
        data = run('cat /etc/os-release')
        for line in data.split('\n'):
            if not line:
                continue
            parts = line.split('=')
            if len(parts) == 2:
                release[parts[0]] = parts[1].strip('\n\r"')

        return release


def linux_distribution():
    """ returns the linux distribution in lower case """
    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=True, capture=True):
        data = os_release()
        return(data['ID'])


def lsb_release():
    """ returns /etc/lsb-release in a dictionary """
    with settings(hide('warnings', 'running'), capture=True):

        _lsb_release = {}
        data = sudo('cat /etc/lsb-release')
        for line in data.split('\n'):
            if not line:
                continue
            parts = line.split('=')
            if len(parts) == 2:
                _lsb_release[parts[0]] = parts[1].strip('\n\r"')

        return _lsb_release


def reboot():

    with settings(warn_only=True, capture=True):
        sudo('shutdown -r now')
        bookshelf2.time_helpers.sleep_for_one_minute()


def restart_service(service, log=False):
    """ restarts a service  """
    with settings():
        if log:
            bookshelf2.logging_helpers.log_yellow(
                'stoping service %s' % service)
        sudo('service %s stop' % service)
        if log:
            bookshelf2.logging_helpers.log_yellow(
                'starting service %s' % service)
        sudo('service %s start' % service)
    return True


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


def add_firewalld_service(service, permanent=True):
    """ adds a firewall rule """

    bookshelf2.pkg.yum_install(packages=['firewalld'])

    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=True, capture=True):
        p = ''
        if permanent:
            p = '--permanent'
        sudo('firewall-cmd --add-service %s %s' % (service, p))
        sudo('systemctl reload firewalld')


def add_firewalld_port(port, permanent=True):
    """ adds a firewall rule """

    bookshelf2.pkg.yum_install(packages=['firewalld'])

    bookshelf2.logging_helpers.log_green('adding a new fw rule: %s' % port)
    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=True, capture=True):
        p = ''
        if permanent:
            p = '--permanent'
        sudo('firewall-cmd --add-port %s %s' % (port, p))
        sudo('systemctl restart firewalld')


def enable_firewalld_service():
    """ install and enables the firewalld service """

    bookshelf2.pkg.yum_install(packages=['firewalld'])
    systemd(service='firewalld', unmask=True)


def install_os_updates(distribution, force=False):
    """ installs OS updates """
    if ('centos' in distribution or
            'rhel' in distribution or
            'redhat' in distribution):
        bookshelf2.logging_helpers.log_green('installing OS updates')
        sudo("yum -y --quiet clean all")
        sudo("yum group mark convert")
        sudo("yum -y --quiet update")

    if ('ubuntu' in distribution or
            'debian' in distribution):
        with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                      warn_only=False, capture=True):
            sudo("DEBIAN_FRONTEND=noninteractive apt-get update")
            if force:
                sudo("sudo DEBIAN_FRONTEND=noninteractive apt-get -y -o "
                     "Dpkg::Options::='--force-confdef' "
                     "-o Dpkg::Options::='--force-confold' upgrade --force-yes")
            else:
                sudo("sudo DEBIAN_FRONTEND=noninteractive apt-get -y -o "
                     "Dpkg::Options::='--force-confdef' -o "
                     "Dpkg::Options::='--force-confold' upgrade")


def install_ubuntu_development_tools():
    """ installs development tools """

    bookshelf2.pkg.apt_install(packages=['build-essential'])


def install_centos_development_tools():
    """ installs development tools """

    bookshelf2.pkg.yum_group_install(groups=['Development tools'])
