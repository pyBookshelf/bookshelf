# vim: ai ts=4 sts=4 et sw=4 ft=python fdm=indent et foldlevel=0

from fabric.api import sudo, local, settings, run
from fabric.context_managers import hide
from fabric.contrib.files import (append as file_append,
                                  contains as file_contains)

from bookshelf.api_v2.os_helpers import install_ubuntu_development_tools

from bookshelf.api_v2.logging_helpers import log_green


def add_epel_yum_repository():
    """
    Install a repository that provides epel packages/updates

    usage:
        add_epel_yum_repository()

    """
    yum_install(packages=["epel-release"])


def add_zfs_apt_repository():
    """ adds the ZFS repository """
    with settings(hide('warnings', 'running', 'stdout'),
                  warn_only=False, capture=True):
        sudo('DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get update')
        install_ubuntu_development_tools()
        apt_install(packages=['software-properties-common',
                              'dkms',
                              'linux-headers-generic',
                              'build-essential'])
        sudo('echo | add-apt-repository ppa:zfs-native/stable')
        sudo('DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get update')
        return True


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
            sudo("DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get install -y %s" % pkg)
        # if we didn't abort above, we should return True
        return True


def apt_install_from_url(pkg_name, url, log=False):
    """ installs a pkg from a url
        p pkg_name: the name of the package to install
        p url: the full URL for the rpm package
    """
    if is_package_installed(distribution='ubuntu', pkg=pkg_name) is False:

        if log:
            log_green(
                "installing %s from %s" % (pkg_name, url))

        with settings(hide('warnings', 'running', 'stdout'),
                      capture=True):

            sudo("wget -c -O %s.deb %s" % (pkg_name, url))
            sudo("dpkg -i %s.deb" % pkg_name)
            # if we didn't abort above, we should return True
            return True


def apt_add_repository_from_apt_string(apt_string, apt_file):
    """ adds a new repository file for apt """

    apt_file_path = '/etc/apt/sources.list.d/%s' % apt_file

    if not file_contains(apt_file_path, apt_string.lower(), use_sudo=True):
        file_append(apt_file_path, apt_string.lower(), use_sudo=True)

        with hide('running', 'stdout'):
            output = sudo("DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get update")
        if 'Some index files failed to download' in output:
            raise SystemExit(1)
        else:
            # if we didn't abort above, we should return True
            return True


def apt_add_key(keyid, keyserver='keyserver.ubuntu.com', log=False):
    """ trust a new PGP key related to a apt-repository """
    if log:
        log_green(
            'trusting keyid %s from %s' % (keyid, keyserver)
        )
    with settings(hide('warnings', 'running', 'stdout')):
        sudo('apt-key adv --keyserver %s --recv %s' % (keyserver, keyid))
    return True


def enable_apt_repositories(prefix, url, version, repositories):
    """ adds an apt repository """
    with settings(hide('warnings', 'running', 'stdout'),
                  warn_only=False, capture=True):
        sudo('apt-add-repository "%s %s %s %s"' % (prefix,
                                                   url,
                                                   version,
                                                   repositories))
        with hide('running', 'stdout'):
            output = sudo("DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get update")
        if 'Some index files failed to download' in output:
            raise SystemExit(1)
        else:
            # if we didn't abort above, we should return True
            return True


def install_gem(gem):
    """ install a particular gem """
    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=False, capture=True):
        # convert 0 into True, any errors will always raise an exception
        return not bool(
            run("gem install %s --no-rdoc --no-ri" % gem).return_code)


def install_python_module(name):
    """ instals a python module using pip """

    with settings(hide('everything'),
                  warn_only=False, capture=True):
        # convert 0 into True, any errors will always raise an exception
        return not bool(
            run('pip --quiet install %s' % name).return_code)


def install_python_module_locally(name):
    """ instals a python module using pip """
    with settings(hide('everything'),
                  warn_only=False, capture=True):
        # convert 0 into True, any errors will always raise an exception
        print(not bool(local('pip --quiet install %s' % name).return_code))
        return not bool(
            local('pip --quiet install %s' % name).return_code)


def install_system_gem(gem):
    """ install a particular gem """
    with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                  warn_only=False, capture=True):
        # convert 0 into True, any errors will always raise an exception
        return not bool(
            sudo("gem install %s --no-rdoc --no-ri" % gem).return_code)


def install_zfs_from_testing_repository():
    # Enable debugging for ZFS modules
    sudo("echo SPL_DKMS_DISABLE_STRIP=y >> /etc/sysconfig/spl")
    sudo("echo ZFS_DKMS_DISABLE_STRIP=y >> /etc/sysconfig/zfs")
    sudo("yum install --quiet -y --enablerepo=zfs-testing zfs")
    sudo("dkms autoinstall")
    sudo("modprobe zfs")


def is_deb_package_installed(pkg):
    """ checks if a particular deb package is installed """

    with settings(hide('everything'),
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


def yum_install(**kwargs):
    """
        installs a yum package
    """
    if 'repo' in kwargs:
        repo = kwargs['repo']

    for pkg in list(kwargs['packages']):
        if is_package_installed(distribution='el', pkg=pkg) is False:
            if 'repo' in locals():
                log_green(
                    "installing %s from repo %s ..." % (pkg, repo))
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
        log_green(
            "installing %s from %s" % (pkg_name, url))
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
