import unittest
from bookshelf.api_v2 import pkg
from fabric.api import sudo, run, local
from bookshelf.tests.api_v2.docker_based_tests import (
    with_ephemeral_container,
    prepare_required_docker_images
)


class AddZfsAptRepositoryTests(unittest.TestCase):

    @with_ephemeral_container(
        verbose=True,
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_add_zfs_apt_repository_installs_repository(self, *args, **kwargs):
        pkg.add_zfs_apt_repository()
        self.assertTrue(
            'zfs-native/stable' in sudo(
                'cat /etc/apt/sources.list.d/*'))

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_add_zfs_apt_repository_returns_True_on_sucess(self, *args,
                                                           **kwargs):
        self.assertTrue(pkg.add_zfs_apt_repository())

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_add_zfs_apt_repository_raises_exception_on_failure(self, *args,
                                                                **kwargs):
        # force a failure by clearing /etc/resolv.conf
        sudo('echo > /etc/resolv.conf')
        with self.assertRaises(SystemExit) as cm:
            pkg.add_zfs_apt_repository()
        self.assertEqual(cm.exception.code, 1)


class AptInstallTests(unittest.TestCase):

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_apt_install_installs_package(self, *args, **kwargs):
        pkg.apt_install(packages=['fish'])
        self.assertTrue(sudo('dpkg-query -l fish '
                             '| grep -q ^.i').return_code == 0)

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_apt_install_returns_true_on_success(self, *args, **kwargs):
        self.assertTrue(
            pkg.apt_install(packages=['fish']))

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_apt_install_raises_exception_on_failure(self, *args, **kwargs):
        sudo('echo > /etc/resolv.conf')
        with self.assertRaises(SystemExit) as cm:
            pkg.apt_install(packages=['fish'])
        self.assertEqual(cm.exception.code, 1)


class AptInstallFromUrlTests(unittest.TestCase):

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_apt_install_from_url_installs_package(self, *args, **kwargs):
        pkg.apt_install_from_url(pkg_name='diveintopython-zh',
                                 url='http://ftp.de.debian.org/debian/pool'
                                 '/main/d/diveintopython-zh/'
                                 'diveintopython-zh_5.4b-1_all.deb')

        self.assertTrue(sudo('dpkg-query -l diveintopython-zh '
                             '| grep -q ^.i').return_code == 0)

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_apt_install_from_url_returns_true_on_success(self, *args,
                                                          **kwargs):
        self.assertTrue(
            pkg.apt_install_from_url(pkg_name='diveintopython-zh',
                                     url='http://ftp.de.debian.org/debian/pool'
                                     '/main/d/diveintopython-zh/'
                                     'diveintopython-zh_5.4b-1_all.deb')
            )

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_apt_install_from_url_raises_exception_on_failure(self, *args,
                                                              **kwargs):
        sudo('echo > /etc/resolv.conf')
        with self.assertRaises(SystemExit) as cm:
            pkg.apt_install_from_url(pkg_name='diveintopython-zh',
                                     url='http://ftp.de.debian.org/debian/pool'
                                     '/main/d/diveintopython-zh/'
                                     'diveintopython-zh_5.4b-1_all.deb')
        self.assertEqual(cm.exception.code, 1)


class AptAddRepositoryFromAptStringTests(unittest.TestCase):

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_apt_add_repository_from_apt_string_installs_repository(self,
                                                                    *args,
                                                                    **kwargs):
        # the keys are not added by apt_add_repository
        sudo('apt-key adv --keyserver keys.gnupg.net --recv-keys '
             '1C4CBDCDCD2EFD2A')
        pkg.apt_add_repository_from_apt_string(
            apt_string='deb-src '
                       'http://repo.percona.com/apt '
                       'trusty main',
            apt_file='test.list')
        self.assertTrue('percona' in sudo(
                        'cat /etc/apt/sources.list.d/*'))

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_apt_add_repository_from_apt_string_returns_true_on_success(
            self,
            *args,
            **kwargs):
                # the keys are not added by apt_add_repository
                sudo('apt-key adv --keyserver keys.gnupg.net --recv-keys '
                     '1C4CBDCDCD2EFD2A')

                self.assertTrue(
                    pkg.apt_add_repository_from_apt_string(
                        apt_string='deb-src '
                                   'http://repo.percona.com/apt '
                                   'trusty main',
                        apt_file='test.list')
                )

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_apt_add_repository_from_url_raises_exception_on_failure(self,
                                                                     *args,
                                                                     **kwargs):
        # the keys are not added by apt_add_repository
        sudo('apt-key adv --keyserver keys.gnupg.net --recv-keys '
             '1C4CBDCDCD2EFD2A')
        sudo('echo > /etc/resolv.conf')
        with self.assertRaises(SystemExit) as cm:
            pkg.apt_add_repository_from_apt_string(
                apt_string='deb-src '
                           'http://repo.percona.com/apt '
                           'trusty main',
                apt_file='test.list')
        self.assertEqual(cm.exception.code, 1)


class AptAddKeyTests(unittest.TestCase):

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_apt_add_key_installs_key(self, *args, **kwargs):
        pkg.apt_add_key(
            keyserver='keys.gnupg.net', keyid='1C4CBDCDCD2EFD2A')
        self.assertTrue(
            'CD2EFD2A' in sudo(
                'apt-key list'))

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_apt_add_key_returns_true_on_success(self, *args, **kwargs):
        self.assertTrue(
            pkg.apt_add_key(
                keyserver='keys.gnupg.net', keyid='1C4CBDCDCD2EFD2A'))

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_apt_add_key_raises_exception_on_failure(self, *args, **kwargs):
        sudo('echo > /etc/resolv.conf')
        with self.assertRaises(SystemExit) as cm:
            pkg.apt_add_key(
                keyserver='keys.gnupg.net', keyid='1C4CBDCDCD2EFD2A')
        self.assertEqual(cm.exception.code, 1)


class EnableAptRepositories(unittest.TestCase):

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_enable_apt_repositories_installs_repository(self,
                                                         *args,
                                                         **kwargs):
        pkg.enable_apt_repositories(
            'deb ',
            'http://archive.ubuntu.com/ubuntu ',
            '$(lsb_release -sc)',
            'main universe restricted multiverse')
        self.assertTrue('universe restricted multiverse' in sudo(
                        'cat /etc/apt/sources.list'))

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_enable_apt_repositories_returns_true_on_success(self,
                                                             *args,
                                                             **kwargs):

        self.assertTrue(
            pkg.enable_apt_repositories(
                'deb ',
                'http://archive.ubuntu.com/ubuntu ',
                '$(lsb_release -sc)',
                'main universe restricted multiverse')
        )

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_enable_apt_repositories_raises_exception_on_failure(self,
                                                                 *args,
                                                                 **kwargs):
        sudo('echo > /etc/resolv.conf')
        with self.assertRaises(SystemExit) as cm:
            pkg.enable_apt_repositories(
                'deb ',
                'http://archive.ubuntu.com/ubuntu ',
                '$(lsb_release -sc)',
                'main universe restricted multiverse')

        self.assertEqual(cm.exception.code, 1)


class InstallSystemGemTests(unittest.TestCase):

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh',
                'centos-7-ruby-ssh'])
    def test_install_system_gem_installs_gem(self, *args, **kwargs):
        pkg.install_system_gem('small')
        self.assertTrue('small' in sudo('gem list'))

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh',
                'centos-7-ruby-ssh'])
    def test_install_system_gem_returns_True_on_success(self, *args, **kwargs):
        self.assertTrue(pkg.install_system_gem('small'))

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh',
                'centos-7-ruby-ssh'])
    def test_install_system_gem_raises_exception_on_failure(self, *args,
                                                            **kwargs):
        with self.assertRaises(SystemExit) as cm:
            pkg.install_system_gem('non_existing_gem')
        self.assertEqual(cm.exception.code, 1)


class InstallGemTests(unittest.TestCase):

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh',
                'centos-7-ruby-ssh'])
    def test_install_gem_installs_gem(self, *args, **kwargs):
        pkg.install_gem('small')
        self.assertTrue('small' in run('gem list'))

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh',
                'centos-7-ruby-ssh'])
    def test_install_gem_returns_True_on_success(self, *args, **kwargs):
        self.assertTrue(pkg.install_gem('small'))

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh',
                'centos-7-ruby-ssh'])
    def test_install_gem_raises_exception_on_failure(self, *args, **kwargs):
        with self.assertRaises(SystemExit) as cm:
            pkg.install_gem('non_existing_gem')
        self.assertEqual(cm.exception.code, 1)


class InstallPythonModuleTests(unittest.TestCase):

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh',
                'centos-7-ruby-ssh'])
    def test_install_python_module_installs_module(self, *args, **kwargs):
        pkg.install_python_module('appdirs')
        self.assertTrue('appdirs' in run('pip list'))

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh',
                'centos-7-ruby-ssh'])
    def test_install_python_module_returns_True_on_success(self, *args,
                                                           **kwargs):
        self.assertTrue(pkg.install_python_module('appdirs'))

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh',
                'centos-7-ruby-ssh'])
    def test_install_python_module_raises_exception_on_failure(self, *args,
                                                               **kwargs):
        with self.assertRaises(SystemExit) as cm:
            pkg.install_python_module('fake-python-module')
        self.assertEqual(cm.exception.code, 1)


class InstallPythonModuleLocallyTests(unittest.TestCase):

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh',
                'centos-7-ruby-ssh'])
    def test_install_python_module_locally_installs_module(self,
                                                           *args, **kwargs):
        pkg.install_python_module_locally('appdirs')
        self.assertTrue('appdirs' in local('pip list', capture=True))

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh',
                'centos-7-ruby-ssh'])
    def test_install_python_module_locally_returns_True_on_success(self,
                                                                   *args,
                                                                   **kwargs):
        self.assertTrue(pkg.install_python_module_locally('appdirs'))

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh',
                'centos-7-ruby-ssh'])
    def test_install_python_module_locally_raises_exception_on_failure(
            self,
            *args,
            **kwargs):
        with self.assertRaises(SystemExit) as cm:
            pkg.install_python_module_locally('fake-python-module')
        self.assertEqual(cm.exception.code, 1)


class IsDebPackageInstalledTests(unittest.TestCase):

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_is_deb_package_installed_returns_true_when_pkg_present(self,
                                                                    *args,
                                                                    **kwargs):
        self.assertTrue(pkg.is_deb_package_installed('bash'))

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_is_deb_package_installed_returns_false_when_pkg_missing(self,
                                                                     *args,
                                                                     **kwargs):
        self.assertFalse(pkg.is_deb_package_installed('fake-deb-pkg'))


class IsPackageInstalledTestsOnUbuntu(unittest.TestCase):

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_is_package_installed_returns_true_when_pkg_present(self,
                                                                *args,
                                                                **kwargs):
        self.assertTrue(pkg.is_package_installed(distribution='ubuntu',
                                                 pkg='bash'))

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh', 'ubuntu-trusty-ruby-ssh'])
    def test_is_package_installed_returns_false_when_pkg_missing(self,
                                                                 *args,
                                                                 **kwargs):
        self.assertFalse(pkg.is_package_installed(distribution='ubuntu',
                                                  pkg='fake-deb-pkg'))


class IsPackageInstalledTestsOnCentos(unittest.TestCase):

    @with_ephemeral_container(images=['centos-7-ruby-ssh'])
    def test_is_package_installed_returns_true_when_pkg_present(self,
                                                                *args,
                                                                **kwargs):
        self.assertTrue(pkg.is_package_installed(distribution='centos-7',
                                                 pkg='bash'))

    @with_ephemeral_container(images=['centos-7-ruby-ssh'])
    def test_is_package_installed_returns_false_when_pkg_missing(self,
                                                                 *args,
                                                                 **kwargs):
        self.assertFalse(pkg.is_package_installed(distribution='centos-7',
                                                  pkg='fake-deb-pkg'))


if __name__ == '__main__':

    prepare_required_docker_images()
    unittest.main(verbosity=4, failfast=True)
