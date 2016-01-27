import unittest
from bookshelf.api_v2 import vagrant
from fabric.api import run, sudo
from bookshelf.tests.api_v2.vagrant_based_tests import (
    with_ephemeral_vagrant_box,
)


class VagrantBasedTests(unittest.TestCase):
    @with_ephemeral_vagrant_box(
        verbose=True,
        images=['ubuntu/trusty64', 'ubuntu/vivid64'])
    def test_vagrant_module(self, *args, **kwargs):

        vagrant.install_virtualbox(distribution='ubuntu',
                                   force_setup=True)
        self.assertTrue(sudo('dpkg-query -l virtualbox-5.0'
                             '| grep -q ^.i').return_code == 0)

        vagrant.install_vagrant(distribution='ubuntu', version='1.7.4')
        run('vagrant init')
        self.assertTrue(
            'Vagrantfile' in run('ls')
        )

        vagrant.install_vagrant_plugin(plugin='ansible')
        self.assertTrue(
            'ansible' in run('vagrant plugin list')
        )

        self.assertTrue(
            vagrant.is_vagrant_plugin_installed('ansible')
        )


if __name__ == '__main__':
    unittest.main(verbosity=4, failfast=True)
