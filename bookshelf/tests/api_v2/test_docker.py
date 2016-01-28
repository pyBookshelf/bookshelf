import unittest
from bookshelf.api_v2 import docker
from fabric.api import sudo
from bookshelf.tests.api_v2.vagrant_based_tests import (
    with_ephemeral_vagrant_box,
)


class VagrantBasedTests(unittest.TestCase):
    @with_ephemeral_vagrant_box(
        verbose=True,
        images=['ubuntu/trusty64', 'ubuntu/vivid64'])
    def test_docker_module(self, *args, **kwargs):

        docker.create_docker_group()
        self.assertTrue(
            'docker:' in sudo('cat /etc/group')
        )

        docker.install_docker()
        self.assertTrue(
            'Docker version ' in sudo(
                'docker --version')
        )

        docker.cache_docker_image_locally('alpine')
        self.assertTrue(
            'alpine ' in sudo(
                'docker images')
        )

        self.assertTrue(
            docker.does_image_exist('alpine')
        )

        self.assertFalse(
            docker.does_image_exist('fake')
        )

        output = sudo('docker run -d ericjperry/busybox-sleep')
        container_id = output.split('\n')[-1]

        self.assertTrue(
            docker.does_container_exist(container_id)
        )

        self.assertFalse(
            docker.does_container_exist('fake')
        )


if __name__ == '__main__':
    unittest.main(verbosity=4, failfast=True)
