import unittest
from fabric.api import sudo
from bookshelf.api_v2.docker_based_tests import DockerBasedTests
from bookshelf.api_v2.decorators import with_ephemeral_container
from bookshelf.api_v2 import os_helpers


class AddUsrLocalBinToPathTests(DockerBasedTests):

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_add_usr_local_bin_to_path_updates_PATH(self, *args, **kwargs):
        os_helpers.add_usr_local_bin_to_path()
        self.assertTrue('/usr/local/bin' in sudo('echo $PATH'))

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_add_user_local_bin_returns_True_on_success(self, *args, **kwargs):
        self.assertTrue(os_helpers.add_usr_local_bin_to_path())

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_add_usr_local_bin_raises_exception_on_failure(self, *args,
                                                           **kwargs):
        # force an exception by removing /etc/profile.d
        sudo('rm -rf /etc/profile.d')

        with self.assertRaises(SystemExit) as cm:
            os_helpers.add_usr_local_bin_to_path()
        self.assertEqual(cm.exception.code, 1)


class ArchTests(DockerBasedTests):

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_arch(self, *args, **kwargs):
        self.assertEquals(os_helpers.arch(), 'x86_64')


class DirAttribsTests(DockerBasedTests):

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_attribs_with_sudo_updates_perms(self, *args, **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        sudo('echo > /tmp/temp1')

        os_helpers.dir_attribs(location='/tmp/temp1',
                                        mode='755',
                                        owner='user1',
                                        group='group1',
                                        recursive=False,
                                        use_sudo=True)

        perms, x, owner, group = sudo('ls -ld /tmp/temp1').split(' ')[0:4]
        self.assertEquals(perms, '-rwxr-xr-x')
        self.assertEquals(owner, 'user1')
        self.assertEquals(group, 'group1')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_attribs_with_sudo_updates_perms_recursively(self,
                                                             *args,
                                                             **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        sudo('mkdir /tmp/temp1')
        sudo('echo > /tmp/temp1/file1')

        os_helpers.dir_attribs(location='/tmp/temp1',
                                        mode='755',
                                        owner='user1',
                                        group='group1',
                                        recursive=True,
                                        use_sudo=True)

        perms, x, owner, group = sudo('ls -ld /tmp/temp1').split(' ')[0:4]
        self.assertEquals(perms, 'drwxr-xr-x')
        self.assertEquals(owner, 'user1')
        self.assertEquals(group, 'group1')

        perms, x, owner, group = sudo('ls -l /tmp/temp1/file1').split(' ')[0:4]
        self.assertEquals(perms, '-rwxr-xr-x')
        self.assertEquals(owner, 'user1')
        self.assertEquals(group, 'group1')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_attribs_without_sudo_updates_perms(self, *args, **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        sudo('echo > /tmp/temp1')

        os_helpers.dir_attribs(location='/tmp/temp1',
                                        mode='755',
                                        owner='user1',
                                        group='group1',
                                        recursive=False,
                                        use_sudo=False)

        perms, x, owner, group = sudo('ls -l /tmp/temp1').split(' ')[0:4]
        self.assertEquals(perms, '-rwxr-xr-x')
        self.assertEquals(owner, 'user1')
        self.assertEquals(group, 'group1')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_attribs_without_sudo_updates_perms_recursively(self,
                                                                *args,
                                                                **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        sudo('mkdir /tmp/temp1')
        sudo('echo > /tmp/temp1/file1')

        os_helpers.dir_attribs(location='/tmp/temp1',
                                        mode='755',
                                        owner='user1',
                                        group='group1',
                                        recursive=True,
                                        use_sudo=False)
        perms, x, owner, group = sudo('ls -ld /tmp/temp1').split(' ')[0:4]
        self.assertEquals(perms, 'drwxr-xr-x')
        self.assertEquals(owner, 'user1')
        self.assertEquals(group, 'group1')

        perms, x, owner, group = sudo('ls -l /tmp/temp1/file1').split(' ')[0:4]
        self.assertEquals(perms, '-rwxr-xr-x')
        self.assertEquals(owner, 'user1')
        self.assertEquals(group, 'group1')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_attribs_returns_True_on_sucess(self, *args, **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        sudo('mkdir /tmp/temp1')
        sudo('echo > /tmp/temp1/file1')

        result = os_helpers.dir_attribs(location='/tmp/temp1',
                                        mode='755',
                                        owner='user1',
                                        group='group1',
                                        recursive=True,
                                        use_sudo=True)

        self.assertTrue(result)

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_attribs_raises_exception_on_failure(self, *args,
                                                     **kwargs):
        with self.assertRaises(SystemExit) as cm:
            os_helpers.dir_attribs(location='/tmp/no-valid-path',
                                            mode='755',
                                            owner='not-a-valid-user',
                                            group='not-a-valid-group',
                                            recursive=True,
                                            use_sudo=False)
        self.assertEqual(cm.exception.code, 1)


class DirEnsureTests(DockerBasedTests):

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_ensure_creates_dir_if_missing(self, *args, **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        os_helpers.dir_ensure(location='/tmp/temp1',
                                       mode='755',
                                       owner='user1',
                                       group='group1',
                                       recursive=False,
                                       use_sudo=False)
        self.assertTrue(sudo('ls -d /tmp/temp1'))

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_ensure_creates_dir_if_missing_as_root(self, *args, **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        os_helpers.dir_ensure(location='/tmp/temp1',
                                       mode='755',
                                       owner='user1',
                                       group='group1',
                                       recursive=False,
                                       use_sudo=True)
        self.assertTrue(sudo('ls -d /tmp/temp1'))

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_ensure_creates_dir_recursive_if_missing(self, *args, **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        os_helpers.dir_ensure(location='/tmp/level1/level2',
                                       mode='755',
                                       owner='user1',
                                       group='group1',
                                       recursive=True,
                                       use_sudo=False)
        self.assertTrue(sudo('ls -d /tmp/level1/level2'))

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_ensure_creates_dir_recursive_if_missing_as_root(self,
                                                                 *args,
                                                                 **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        os_helpers.dir_ensure(location='/tmp/level1/level2',
                                       mode='755',
                                       owner='user1',
                                       group='group1',
                                       recursive=True,
                                       use_sudo=True)
        self.assertTrue(sudo('ls -d /tmp/level1/level2'))

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_ensure_with_sudo_updates_perms(self, *args, **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')

        os_helpers.dir_ensure(location='/tmp/temp1',
                                       mode='700',
                                       owner='user1',
                                       group='group1',
                                       recursive=False,
                                       use_sudo=True)

        perms, x, owner, group = sudo('ls -ld /tmp/temp1').split(' ')[0:4]
        self.assertEquals(perms, 'drwx------')
        self.assertEquals(owner, 'user1')
        self.assertEquals(group, 'group1')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_ensure_with_sudo_updates_perms_recursively(self,
                                                            *args,
                                                            **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        sudo('mkdir /tmp/level1')
        sudo('mkdir /tmp/level1/level2')

        os_helpers.dir_ensure(location='/tmp/level1',
                                       mode='700',
                                       owner='user1',
                                       group='group1',
                                       recursive=True,
                                       use_sudo=True)

        for folder in ['/tmp/level1', '/tmp/level1/level2']:
            perms, x, owner, group = sudo('ls -ld %s' % folder).split(' ')[0:4]
            self.assertEquals(perms, 'drwx------')
            self.assertEquals(owner, 'user1')
            self.assertEquals(group, 'group1')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_ensure_without_sudo_updates_perms(self, *args, **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')

        os_helpers.dir_ensure(location='/tmp/temp1',
                                       mode='700',
                                       owner='user1',
                                       group='group1',
                                       recursive=False,
                                       use_sudo=False)

        perms, x, owner, group = sudo('ls -ld /tmp/temp1').split(' ')[0:4]
        self.assertEquals(perms, 'drwx------')
        self.assertEquals(owner, 'user1')
        self.assertEquals(group, 'group1')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_ensure_without_sudo_updates_perms_recursively(self,
                                                               *args,
                                                               **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        sudo('mkdir -p /tmp/level1/level2')

        os_helpers.dir_ensure(location='/tmp/level1',
                                       mode='700',
                                       owner='user1',
                                       group='group1',
                                       recursive=True,
                                       use_sudo=False)
        for folder in ['/tmp/level1', '/tmp/level1/level2']:
            perms, x, owner, group = sudo('ls -ld %s' % folder).split(' ')[0:4]
            self.assertEquals(perms, 'drwx------')
            self.assertEquals(owner, 'user1')
            self.assertEquals(group, 'group1')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_ensure_returns_True_on_sucess(self, *args, **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        sudo('mkdir /tmp/temp1')

        result = os_helpers.dir_ensure(location='/tmp/temp1',
                                       mode='755',
                                       owner='user1',
                                       group='group1',
                                       recursive=True,
                                       use_sudo=True)
        self.assertTrue(result)

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_ensure_raises_exception_on_failure(self, *args, **kwargs):
        with self.assertRaises(SystemExit) as cm:
            os_helpers.dir_ensure(location='/tmp/no-valid-path',
                                           mode='755',
                                           owner='not-a-valid-user',
                                           group='not-a-valid-group',
                                           recursive=True,
                                           use_sudo=False)
        self.assertEqual(cm.exception.code, 1)


class DirExistsTests(DockerBasedTests):

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_exists_returns_True(self, *args, **kwargs):
        # make sure we have a /tmp/temp1 folder
        sudo('mkdir /tmp/temp1')
        self.assertTrue(
            os_helpers.dir_exists(location='/tmp/temp1',
                                  use_sudo=False)
        )

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_exists_returns_False_if_missing(self, *args, **kwargs):
        self.assertFalse(
            os_helpers.dir_exists(location='/tmp/temp1',
                                  use_sudo=False)
        )

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_exists_returns_True_with_sudo(self, *args, **kwargs):
        # make sure we have a level2 folder only accessible by root
        sudo('mkdir -p /tmp/level1/level2')
        sudo('chmod 700 /tmp/level1')
        self.assertTrue(
            os_helpers.dir_exists(location='/tmp/level1/level2',
                                  use_sudo=True)
        )

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_exists_returns_False_if_missing_with_sudo(self,
                                                           *args,
                                                           **kwargs):
        self.assertFalse(
            os_helpers.dir_exists(location='/tmp/level1/level2',
                                  use_sudo=False)
        )

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_dir_exists_returns_False_without_sudo_when_folder_is_root_owned(
            self, *args, **kwargs):
        # make sure we have a level2 folder only accessible by root
        sudo('mkdir -p /tmp/level1/level2')
        sudo('chmod 700 /tmp/level1')
        self.assertTrue(
            os_helpers.dir_exists(location='/tmp/level1/level2',
                                  use_sudo=False)
        )


class DisableEnvResetOnSudoTests(DockerBasedTests):

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_disable_env_reset_on_sudo_updates_sudoers(self, *args, **kwargs):
        # distros have different /etc/sudoers file contents, so we will make
        # sure we target the correct contents for each linux distribution.
        os = sudo('cat /etc/os-release').lower()

        # update /etc/sudoers
        os_helpers.disable_env_reset_on_sudo()

        # we rely on md5sum of the file so check if our changes were applied
        # correctly
        md5sum = sudo('md5sum /etc/sudoers').split(' ')[0]
        if 'ubuntu' in os:
            self.assertEquals(md5sum,
                              '5328c9fb99ad099d2d18a45bc67ee024')
        if 'centos' in os:
            sudo('md5sum /etc/sudoers')
            self.assertEquals(md5sum,
                              '8d7a8d9630ccb427c5adbeccf6846415')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_disable_env_reset_on_sudo_is_idempodent(self, *args, **kwargs):
        # distros have different /etc/sudoers file contents, so we will make
        # sure we target the correct contents for each linux distribution.
        os = sudo('cat /etc/os-release').lower()

        # update /etc/sudoers twice.
        # the entries on /etc/sudoers should only be inserted once
        os_helpers.disable_env_reset_on_sudo()

        # we rely on md5sum of the file so check if our changes were applied
        # correctly
        md5sum = sudo('md5sum /etc/sudoers').split(' ')[0]
        if 'ubuntu' in os:
            self.assertEquals(md5sum,
                              '5328c9fb99ad099d2d18a45bc67ee024')
        if 'centos' in os:
            sudo('md5sum /etc/sudoers')
            self.assertEquals(md5sum,
                              '8d7a8d9630ccb427c5adbeccf6846415')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_disable_env_reset_returns_True(self, *args, **kwargs):
        self.assertTrue(os_helpers.disable_env_reset_on_sudo())

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_disable_env_reset_on_sudo_raises_exception_on_failure(self,
                                                                   *args,
                                                                   **kwargs):
        # this will make if fail
        sudo('rm /etc/sudoers')
        with self.assertRaises(SystemExit) as cm:
            os_helpers.disable_env_reset_on_sudo()
        self.assertEqual(cm.exception.code, 1)


class DisableRequirettyOnSudoersTests(DockerBasedTests):

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_disable_requiretty_on_sudoers_updates_sudoers(self,
                                                           *args,
                                                           **kwargs):
        # distros have different /etc/sudoers file contents, so we will make
        # sure we target the correct contents for each linux distribution.
        os = sudo('cat /etc/os-release').lower()

        sudo('cat /etc/sudoers')

        # we rely on md5sum of the file so check if our changes were applied
        # correctly
        md5sum = sudo('md5sum /etc/sudoers').split(' ')[0]
        if 'ubuntu' in os:
            # our docker image doesn't contain the entry we need so...
            sudo('echo "Defaults    requiretty" >> /etc/sudoers')

            # update /etc/sudoers
            os_helpers.disable_requiretty_on_sudoers()

            self.assertEquals(md5sum,
                              'e8e73f16ed73309df7574c12fbcc0af7')
        if 'centos' in os:
            sudo('md5sum /etc/sudoers')

            # update /etc/sudoers
            os_helpers.disable_requiretty_on_sudoers()

            sudo('cat /etc/sudoers')
            self.assertEquals(md5sum,
                              'ef817e657e3ffa6b0a88f59e3fc7241b')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_disable_requiretty_on_sudoers_is_idempodent(self,
                                                         *args,
                                                         **kwargs):
        # distros have different /etc/sudoers file contents, so we will make
        # sure we target the correct contents for each linux distribution.
        os = sudo('cat /etc/os-release').lower()

        # we rely on md5sum of the file so check if our changes were applied
        # correctly
        md5sum = sudo('md5sum /etc/sudoers').split(' ')[0]
        if 'ubuntu' in os:
            # our docker image doesn't contain the entry we need so...
            sudo('echo "Defaults    requiretty" >> /etc/sudoers')

            # update /etc/sudoers, twice
            # the entries on /etc/sudoers should only be inserted once
            os_helpers.disable_requiretty_on_sudoers()
            os_helpers.disable_requiretty_on_sudoers()

            self.assertEquals(md5sum,
                              'e8e73f16ed73309df7574c12fbcc0af7')
        if 'centos' in os:
            # update /etc/sudoers
            # the entries on /etc/sudoers should only be inserted once
            os_helpers.disable_requiretty_on_sudoers()
            os_helpers.disable_requiretty_on_sudoers()

            self.assertEquals(md5sum,
                              'ef817e657e3ffa6b0a88f59e3fc7241b')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_disable_requiretty_on_sudoers_returns_True(self, *args, **kwargs):
        self.assertTrue(os_helpers.disable_requiretty_on_sudoers())

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_disable_requiretty_on_sudoers_raises_exception_on_failure(
            self, *args, **kwargs):
        # this will make if fail
        sudo('rm /etc/sudoers')
        with self.assertRaises(SystemExit) as cm:
            os_helpers.disable_requiretty_on_sudoers()
        self.assertEqual(cm.exception.code, 1)


class DisableRequirettyOnSshdConfigTests(DockerBasedTests):
    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_disable_requiretty_on_sshd_config_updates_sshd_config(self,
                                                                   *args,
                                                                   **kwargs):
        # distros have different /etc/sshd_config file contents, so we will make
        # sure we target the correct contents for each linux distribution.
        os = sudo('cat /etc/os-release').lower()

        # this is missing on our docker images
        sudo('echo "Requiretty yes" >> /etc/ssh/sshd_config')
        # update /etc/sshd_config
        os_helpers.disable_requiretty_on_sshd_config()
        # we rely on md5sum of the file so check if our changes were applied
        # correctly
        md5sum = sudo('md5sum /etc/ssh/sshd_config').split(' ')[0]

        if 'ubuntu' in os:
            self.assertEquals(md5sum,
                              '208abf29a29805dbfe4ac954bb50b0c9')
        if 'centos' in os:
            self.assertEquals(md5sum,
                              '9af1ec6efaf3bf271fc1838613fa0778')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_disable_requiretty_on_sshd_config_is_idempodent(self,
                                                             *args,
                                                             **kwargs):
        # distros have different /etc/sshd_config file contents, so we will make
        # sure we target the correct contents for each linux distribution.
        os = sudo('cat /etc/os-release').lower()

        # this is missing on our docker images
        sudo('echo "Requiretty yes" >> /etc/ssh/sshd_config')
        # update /etc/sshd_config, twice
        os_helpers.disable_requiretty_on_sshd_config()
        os_helpers.disable_requiretty_on_sshd_config()
        # we rely on md5sum of the file so check if our changes were applied
        # correctly
        md5sum = sudo('md5sum /etc/ssh/sshd_config').split(' ')[0]

        if 'ubuntu' in os:
            self.assertEquals(md5sum,
                              '208abf29a29805dbfe4ac954bb50b0c9')
        if 'centos' in os:
            self.assertEquals(md5sum,
                              '9af1ec6efaf3bf271fc1838613fa0778')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_disable_requiretty_on_sshd_config_returns_True(self,
                                                            *args,
                                                            **kwargs):
        self.assertTrue(os_helpers.disable_requiretty_on_sshd_config())

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_disable_requiretty_on_sshd_config_raises_exception_on_failure(
            self, *args, **kwargs):
        # this will make if fail
        sudo('rm /etc/ssh/sshd_config')
        with self.assertRaises(SystemExit) as cm:
            os_helpers.disable_requiretty_on_sshd_config()
        self.assertEqual(cm.exception.code, 1)


class DisableSelinuxTests(DockerBasedTests):

    @unittest.skip("Unable to test SElinux on a container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_disable_selinux_disables_selinux(self, *args, **kwargs):
        self.assertTrue(False)

    @unittest.skip("Unable to test SElinux on a container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_add_disable_selinux_returns_True_on_sucess(self, *args, **kwargs):
        self.assertTrue(False)

    @unittest.skip("Unable to test SElinux on a container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_disable_selinux_raises_exception_on_failure(self, *args, **kwargs):
        self.assertTrue(False)

        with self.assertRaises(SystemExit) as cm:
            self.assertTrue(True)
        self.assertEqual(cm.exception.code, 1)


class EnableSelinuxTests(DockerBasedTests):

    @unittest.skip("Unable to test SElinux on a container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_enable_selinux_enables_selinux(self, *args, **kwargs):
        self.assertTrue(False)

    @unittest.skip("Unable to test SElinux on a container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_add_enable_selinux_returns_True_on_sucess(self, *args, **kwargs):
        self.assertTrue(False)

    @unittest.skip("Unable to test SElinux on a container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_enable_selinux_raises_exception_on_failure(self, *args, **kwargs):
        with self.assertRaises(SystemExit) as cm:
            self.assertTrue(True)
        self.assertEqual(cm.exception.code, 1)


class FileAttribsTests(DockerBasedTests):
    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_file_attribs_with_sudo_updates_perms(self, *args, **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        sudo('echo > /tmp/temp1')

        os_helpers.file_attribs(location='/tmp/temp1',
                                         mode='755',
                                         owner='user1',
                                         group='group1',
                                         recursive=False,
                                         use_sudo=True)

        perms, x, owner, group = sudo('ls -l /tmp/temp1').split(' ')[0:4]
        self.assertEquals(perms, '-rwxr-xr-x')
        self.assertEquals(owner, 'user1')
        self.assertEquals(group, 'group1')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_file_attribs_with_sudo_updates_perms_recursively(self,
                                                              *args,
                                                              **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        sudo('mkdir /tmp/temp1')
        sudo('echo > /tmp/temp1/file1')

        os_helpers.file_attribs(location='/tmp/temp1',
                                         mode='755',
                                         owner='user1',
                                         group='group1',
                                         recursive=True,
                                         use_sudo=True)

        perms, x, owner, group = sudo('ls -ld /tmp/temp1').split(' ')[0:4]
        self.assertEquals(perms, 'drwxr-xr-x')
        self.assertEquals(owner, 'user1')
        self.assertEquals(group, 'group1')

        perms, x, owner, group = sudo('ls -l /tmp/temp1/file1').split(' ')[0:4]
        self.assertEquals(perms, '-rwxr-xr-x')
        self.assertEquals(owner, 'user1')
        self.assertEquals(group, 'group1')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_file_attribs_without_sudo_updates_perms(self, *args, **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        sudo('echo > /tmp/temp1')

        os_helpers.file_attribs(location='/tmp/temp1',
                                         mode='755',
                                         owner='user1',
                                         group='group1',
                                         recursive=False,
                                         use_sudo=False)

        perms, x, owner, group = sudo('ls -l /tmp/temp1').split(' ')[0:4]
        self.assertEquals(perms, '-rwxr-xr-x')
        self.assertEquals(owner, 'user1')
        self.assertEquals(group, 'group1')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_file_attribs_without_sudo_updates_perms_recursively(self,
                                                                 *args,
                                                                 **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        sudo('mkdir /tmp/temp1')
        sudo('echo > /tmp/temp1/file1')

        os_helpers.file_attribs(location='/tmp/temp1',
                                         mode='755',
                                         owner='user1',
                                         group='group1',
                                         recursive=True,
                                         use_sudo=False)
        perms, x, owner, group = sudo('ls -ld /tmp/temp1').split(' ')[0:4]
        self.assertEquals(perms, 'drwxr-xr-x')
        self.assertEquals(owner, 'user1')
        self.assertEquals(group, 'group1')

        perms, x, owner, group = sudo('ls -l /tmp/temp1/file1').split(' ')[0:4]
        self.assertEquals(perms, '-rwxr-xr-x')
        self.assertEquals(owner, 'user1')
        self.assertEquals(group, 'group1')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_file_attribs_returns_True_on_sucess(self, *args, **kwargs):
        # make sure we have a user1 and group1 on our docker instance
        sudo('/usr/sbin/useradd user1')
        sudo('/usr/sbin/groupadd group1')
        sudo('mkdir /tmp/temp1')
        sudo('echo > /tmp/temp1/file1')

        result = os_helpers.file_attribs(location='/tmp/temp1',
                                         mode='755',
                                         owner='user1',
                                         group='group1',
                                         recursive=True,
                                         use_sudo=True)

        self.assertTrue(result)

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_file_attribs_raises_exception_on_failure(self,
                                                      *args,
                                                      **kwargs):
        with self.assertRaises(SystemExit) as cm:
            os_helpers.file_attribs(location='/tmp/no-valid-path',
                                             mode='755',
                                             owner='not-a-valid-user',
                                             group='not-a-valid-group',
                                             recursive=True,
                                             use_sudo=False)
        self.assertEqual(cm.exception.code, 1)


class OsReleaseTests(DockerBasedTests):

    @with_ephemeral_container(
        distributions=['ubuntu-vivid'])
    def test_os_release_on_ubuntu_vivid_returns_os_release_string(self,
                                                                  *args,
                                                                  **kwargs):
        print(os_helpers.os_release())
        self.assertEquals(os_helpers.os_release(),
                          {'SUPPORT_URL': 'http://help.ubuntu.com/',
                           'NAME': 'Ubuntu',
                           'ID_LIKE': 'debian',
                           'VERSION_ID': '15.04',
                           'BUG_REPORT_URL': 'http://bugs.launchpad.net/ubuntu/',  # noqa
                           'PRETTY_NAME': 'Ubuntu 15.04',
                           'VERSION': '15.04 (Vivid Vervet)',
                           'HOME_URL': 'http://www.ubuntu.com/',
                           'ID': 'ubuntu'}
        )

    @with_ephemeral_container(
        distributions=['ubuntu-trusty'])
    def test_os_release_on_ubuntu_trusty_returns_os_release_string(self,
                                                                   *args,
                                                                   **kwargs):
        self.assertEquals(os_helpers.os_release(),
                          {'SUPPORT_URL': 'http://help.ubuntu.com/',
                           'NAME': 'Ubuntu',
                           'ID_LIKE': 'debian',
                           'VERSION_ID': '14.04',
                           'BUG_REPORT_URL': 'http://bugs.launchpad.net/ubuntu/',  # noqa
                           'PRETTY_NAME': 'Ubuntu 14.04.3 LTS',
                           'VERSION': '14.04.3 LTS, Trusty Tahr',
                           'HOME_URL': 'http://www.ubuntu.com/',
                           'ID': 'ubuntu'}
        )

    @with_ephemeral_container(
        distributions=['centos-7'])
    def test_os_release_on_centos_7_returns_os_release_string(self,
                                                              *args,
                                                              **kwargs):
        self.assertEquals(os_helpers.os_release(),
                          {'NAME': 'CentOS Linux',
                           'ANSI_COLOR': '0;31',
                           'ID_LIKE': 'rhel fedora',
                           'VERSION_ID': '7',
                           'BUG_REPORT_URL': 'https://bugs.centos.org/',
                           'CENTOS_MANTISBT_PROJECT': 'CentOS-7',
                           'PRETTY_NAME': 'CentOS Linux 7 (Core)',
                           'VERSION': '7 (Core)',
                           'REDHAT_SUPPORT_PRODUCT_VERSION': '7',
                           'CENTOS_MANTISBT_PROJECT_VERSION': '7',
                           'REDHAT_SUPPORT_PRODUCT': 'centos',
                           'HOME_URL': 'https://www.centos.org/',
                           'CPE_NAME': 'cpe:/o:centos:centos:7',
                           'ID': 'centos'})


class LinuxDistributionTests(DockerBasedTests):

    @with_ephemeral_container(
        distributions=['centos-7'])
    def test_linux_distribution_on_centos_returns_centos_string(self,
                                                                *args,
                                                                **kwargs):
        self.assertTrue(os_helpers.linux_distribution(), 'centos')

    @with_ephemeral_container(
        distributions=['ubuntu-trusty'])
    def test_linux_distribution_on_ubuntu_trusty_returns_ubuntu_string(
            self, *args, **kwargs):
        self.assertTrue(os_helpers.linux_distribution(), 'ubuntu')

    @with_ephemeral_container(
        distributions=['ubuntu-vivid'])
    def test_linux_distribution_on_ubuntu_vivid_returns_ubuntu_string(
            self, *args, **kwargs):
        self.assertTrue(os_helpers.linux_distribution(), 'ubuntu')


class LsbReleaseTests(DockerBasedTests):
    @with_ephemeral_container(
        distributions=['ubuntu-vivid'])
    def test_lsb_release_on_ubuntu_vivid_returns_lsb_release_string(self,
                                                                    *args,
                                                                    **kwargs):
        sudo('apt-get update')
        sudo('apt-get -y install lsb-release')
        self.assertEquals(os_helpers.lsb_release(),
                          {'DISTRIB_CODENAME': 'vivid',
                           'DISTRIB_RELEASE': '15.04',
                           'DISTRIB_ID': 'Ubuntu',
                           'DISTRIB_DESCRIPTION': 'Ubuntu 15.04'}
                          )

    @with_ephemeral_container(
        distributions=['ubuntu-trusty'])
    def test_lsb_release_on_ubuntu_trusty_returns_lsb_release_string(self,
                                                                     *args,
                                                                     **kwargs):
        sudo('apt-get update')
        sudo('apt-get -y install lsb-release')
        self.assertEquals(os_helpers.lsb_release(),
                          {'DISTRIB_CODENAME': 'trusty',
                           'DISTRIB_RELEASE': '14.04',
                           'DISTRIB_ID': 'Ubuntu',
                           'DISTRIB_DESCRIPTION': 'Ubuntu 14.04.3 LTS'}
                          )

    @unittest.skip("/etc/lsb-release not available on centos")
    @with_ephemeral_container(
        distributions=['centos-7'], verbose=True)
    def test_lsb_release_on_centos_7_lsb_release_string(self,
                                                        *args,
                                                        **kwargs):
        sudo('yum install -y redhat-lsb-core')
        self.assertEquals(os_helpers.lsb_release(),
                          {'DISTRIB_CODENAME': 'trusty',
                           'DISTRIB_RELEASE': '14.04',
                           'DISTRIB_ID': 'Ubuntu',
                           'DISTRIB_DESCRIPTION': 'Ubuntu 14.04.3 LTS'}
                          )


class RebootTests(DockerBasedTests):

    @unittest.skip("Unable to test a system reboot on a container")
    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty', 'centos-7'])
    def test_reboot_returns_reboot_string(self, *args, **kwargs):
        self.assertTrue(False)


class RestartServiceTests(DockerBasedTests):

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty'])
    def test_restart_service__on_ubuntu_restarts_service(self, *args, **kwargs):
        sudo('apt-get update')
        sudo('apt-get install -y xinetd')
        sudo('service xinetd start')

        pid_before_restart = sudo(
            'ps -ef | grep xinetd | grep -v grep | awk "{ print $2 }"')
        os_helpers.restart_service('xinetd')
        pid_after_restart = sudo(
            'ps -ef | grep xinetd | grep -v grep | awk "{ print $2 }"')
        self.assertNotEquals(pid_before_restart, pid_after_restart)

    @unittest.skip("Required systemd running on the container")
    @with_ephemeral_container(
        distributions=['centos-7'])
    def test_restart_service__on_centos_restarts_service(self, *args, **kwargs):
        sudo('yum -y install xinetd')
        sudo('service xinetd start')

        pid_before_restart = sudo(
            'ps -ef | grep xinetd | grep -v grep | awk "{ print $2 }"')
        os_helpers.restart_service('xinetd')
        pid_after_restart = sudo(
            'ps -ef | grep xinetd | grep -v grep | awk "{ print $2 }"')
        self.assertNotEquals(pid_before_restart, pid_after_restart)

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty'])
    def test_restart_service_on_ubuntu_returns_True_on_success(self,
                                                               *args,
                                                               **kwargs):
        sudo('apt-get update')
        sudo('apt-get install -y xinetd')
        sudo('service xinetd start')

        self.assertTrue(os_helpers.restart_service('xinetd'))

    @unittest.skip("Required systemd running on the container")
    @with_ephemeral_container(
        distributions=['centos-7'])
    def test_restart_service_on_centos_returns_True_on_success(self,
                                                               *args,
                                                               **kwargs):
        sudo('apt-get update')
        sudo('apt-get install -y xinetd')
        sudo('service xinetd start')

        self.assertTrue(os_helpers.restart_service('xinetd'))

    @with_ephemeral_container(
        distributions=['ubuntu-vivid', 'ubuntu-trusty'])
    def test_restart_service_on_ubuntu_raises_exception_on_failure(self,
                                                                   *args,
                                                                   **kwargs):
        with self.assertRaises(SystemExit) as cm:
            os_helpers.restart_service('fake-service')
        self.assertEqual(cm.exception.code, 1)

    @unittest.skip("Required systemd running on the container")
    @with_ephemeral_container(
        distributions=['centos-7'])
    def test_restart_service_on_centos_raises_exception_on_failure(self,
                                                                   *args,
                                                                   **kwargs):
        with self.assertRaises(SystemExit) as cm:
            os_helpers.restart_service('fake-service')
        self.assertEqual(cm.exception.code, 1)


class SystemdTests(DockerBasedTests):

    @unittest.skip("Required systemd running on the container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_systemd_returns_systemd_string(self, *args, **kwargs):
        self.assertTrue(False)

    @unittest.skip("Required systemd running on the container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_systemd_returns_True_on_sucess(self, *args, **kwargs):
        self.assertTrue(False)

    @unittest.skip("Required systemd running on the container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_systemd_raises_exception_on_failure(self, *args, **kwargs):
        self.assertTrue(False)

        with self.assertRaises(SystemExit) as cm:
            self.assertTrue(True)
        self.assertEqual(cm.exception.code, 1)


class AddFirewalldServiceTests(DockerBasedTests):

    @unittest.skip("Required systemd running on the container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_add_firewalld_service_adds_service(self, *args, **kwargs):
        self.assertTrue(False)

    @unittest.skip("Required systemd running on the container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_add_frewalld_service_returns_True_on_sucess(self, *args, **kwargs):
        self.assertTrue(False)

    @unittest.skip("Required systemd running on the container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_add_firewalld_service_raises_exception_on_failure(self,
                                                               *args,
                                                               **kwargs):
        self.assertTrue(False)

        with self.assertRaises(SystemExit) as cm:
            self.assertTrue(True)
        self.assertEqual(cm.exception.code, 1)


class AddFirewalldPortTests(DockerBasedTests):

    @unittest.skip("Required systemd running on the container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_add_firewalld_port_adds_port(self, *args, **kwargs):
        self.assertTrue(False)

    @unittest.skip("Required systemd running on the container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_add_firewalld_port_returns_True_on_sucess(self, *args, **kwargs):
        self.assertTrue(False)

    @unittest.skip("Required systemd running on the container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_add_firewalld_port_raises_exception_on_failure(self,
                                                            *args,
                                                            **kwargs):
        self.assertTrue(False)

        with self.assertRaises(SystemExit) as cm:
            self.assertTrue(True)
        self.assertEqual(cm.exception.code, 1)


class EnableFirewalldServiceTests(DockerBasedTests):

    @unittest.skip("Required systemd running on the container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_enable_firewalld_service_enables_service(self, *args, **kwargs):
        self.assertTrue(False)

    @unittest.skip("Required systemd running on the container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_enable_firewalld_service_returns_True_on_sucess(self,
                                                             *args,
                                                             **kwargs):
        self.assertTrue(False)

    @unittest.skip("Required systemd running on the container")
    @with_ephemeral_container(distributions=['centos-7'])
    def test_enable_firewalld_service_raises_exception_on_failure(self,
                                                                  *args,
                                                                  **kwargs):
        self.assertTrue(False)

        with self.assertRaises(SystemExit) as cm:
            self.assertTrue(True)
        self.assertEqual(cm.exception.code, 1)


if __name__ == '__main__':
    unittest.main()
