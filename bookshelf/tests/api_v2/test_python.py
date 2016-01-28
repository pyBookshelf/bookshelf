
import unittest
from bookshelf.api_v2 import python
from fabric.api import sudo, run
from bookshelf.tests.api_v2.docker_based_tests import (
    with_ephemeral_container,
    prepare_required_docker_images
)


class UpdateSystemPipToLatestPipUbuntuTests(unittest.TestCase):
    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh'])
    def test_update_system_pip_to_latest_pip(self, *args, **kwargs):
        python.update_system_pip_to_latest_pip()

        self.assertRegexpMatches(
            sudo('pip --version'),
            'pip 8.* from.*'
        )


class UpdateToLatestPipUbuntuTests(unittest.TestCase):
    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh'])
    def test_update_to_latest_pip(self, *args, **kwargs):
        python.update_to_latest_pip()

        self.assertRegexpMatches(
            run('pip --version'),
            'pip 8.* from.*'
        )


if __name__ == '__main__':

    prepare_required_docker_images()
    unittest.main(verbosity=4, failfast=True)
