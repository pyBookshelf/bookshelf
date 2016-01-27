import unittest
from bookshelf.api_v2 import file
from fabric.api import sudo, run
from bookshelf.tests.api_v2.docker_based_tests import (
    with_ephemeral_container,
    prepare_required_docker_images
)


class InsertLineInFileAfterRegexTests(unittest.TestCase):

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh',
                'centos-7-ruby-ssh'])
    def test_insert_line_in_file_after_regex_returns_True_when_changed(
            self,
            *args,
            **kwargs):

        contents = '\n'.join(
            [
                'Here I am,',
                'on my bicycle',
                'cool, init?'
            ]
        )

        run('echo "%s" > /tmp/test' % contents)

        # it should return True when changed
        self.assertTrue(
            file.insert_line_in_file_after_regex('/tmp/test',
                                                 'Look mum, no hands',
                                                 '.*on.*bicycle')
        )

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh',
                'centos-7-ruby-ssh'])
    def test_insert_line_in_file_after_regex_returns_False_when_not_changed(
            self,
            *args,
            **kwargs):

        contents = '\n'.join(
            [
                'Here I am,',
                'on my bicycle',
                'Look mum, no hands',
                'cool, init?'
            ]
        )

        run('echo "%s" > /tmp/test' % contents)

        # it should return False in nothing changed
        self.assertFalse(
            file.insert_line_in_file_after_regex('/tmp/test',
                                                 'Look mum, no hands',
                                                 '.*on.*bicycle')
        )

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh',
                'centos-7-ruby-ssh'])
    def test_insert_line_in_file_after_regex_inserts_line(self,
                                                          *args,
                                                          **kwargs):

        contents = '\n'.join(
            [
                'Here I am,',
                'on my bicycle',
                'cool, init?'
            ]
        )

        expected = '\r\n'.join(
            [
                'Here I am,',
                'on my bicycle',
                'Look mum, no hands',
                'cool, init?'
            ]
        )

        run('echo "%s" > /tmp/test' % contents)

        file.insert_line_in_file_after_regex('/tmp/test',
                                             'Look mum, no hands',
                                             '.*on.*bicycle')

        self.assertEqual(sudo('cat /tmp/test'), expected)

    @with_ephemeral_container(
        images=['ubuntu-vivid-ruby-ssh',
                'ubuntu-trusty-ruby-ssh',
                'centos-7-ruby-ssh'])
    def test_insert_line_in_file_after_regex_raises_Exception_on_failure(
            self,
            *args,
            **kwargs):

        with self.assertRaises(SystemExit) as cm:
            file.insert_line_in_file_after_regex('/tmp/test',
                                                 'Look mum, no hands',
                                                 '.*on.*bicycle')
        self.assertEqual(cm.exception.code, 1)


if __name__ == '__main__':

    prepare_required_docker_images()
    unittest.main(verbosity=4, failfast=True)
