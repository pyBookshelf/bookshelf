import unittest
from bookshelf.api_v2 import git
from fabric.api import run, sudo
from bookshelf.tests.api_v2.docker_based_tests import (
    with_ephemeral_container,
    prepare_required_docker_images
)


class InstallRecentGitFromSourceTests(unittest.TestCase):

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh'])
    def test_on_ubuntu_install_recent_git_from_source_installs_git(self,
                                                                   *args,
                                                                   **kwargs):
        sudo('apt-get -y install wget zlib1g-dev libperl-dev')
        sudo('apt-get -y install build-essential')
        git.install_recent_git_from_source(version='2.4.6',
                                           prefix='/usr/local')

        self.assertTrue(
            '2.4.6' in run('git --version')
        )

    @with_ephemeral_container(
        images=['centos-7-ruby-ssh'])
    def test_on_centos_install_recent_git_from_source_installs_git(self,
                                                                   *args,
                                                                   **kwargs):
        sudo('yum -y install wget zlib-devel perl-devel')
        sudo('yum -y groupinstall "Development Tools"')
        git.install_recent_git_from_source(version='2.4.6',
                                           prefix='/usr/local')
        self.assertTrue(
            '2.4.6' in run('git --version')
        )


class GitCloneTests(unittest.TestCase):
    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh'])
    def test_on_ubuntu_git_clone_clones_repository(self, *args, **kwargs):
        sudo('apt-get -y install git')
        git.git_clone('https://github.com/fabric/fabric.git', 'fabric')

        self.assertTrue(
            'fabric' in run('ls')
        )





if __name__ == '__main__':

    prepare_required_docker_images()
    unittest.main(verbosity=4, failfast=True)
