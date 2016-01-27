import unittest
from bookshelf.api_v2 import rackspace
import novaclient
import vcr
import mock
from collections import OrderedDict
import os



class ConnectToRackspaceTests(unittest.TestCase):

    @vcr.use_cassette('fixtures/vcr_ConnectToRackspace.yml',
                      decode_compressed_response=True)
    def test_connect_to_rackspace_returns_connection_object(self,
                                                            *args,
                                                            **kwargs):

        conn = rackspace.connect_to_rackspace(os.environ.get('OS_REGION_NAME'),
                                              os.environ.get('OS_USERNAME'),
                                              os.environ.get('OS_PASSWORD'),
                                              )
        self.assertTrue(isinstance(conn, novaclient.v2.client.Client))


class CreateRackspaceImageTests(unittest.TestCase):
    @vcr.use_cassette('fixtures/vcr_CreateRackspaceImage.yml')
    def test_CreateRackspaceImage(self,
                                  *args,
                                  **kwargs):

        conn = rackspace.connect_to_rackspace(os.environ.get('OS_REGION_NAME'),
                                              os.environ.get('OS_USERNAME'),
                                              os.environ.get('OS_PASSWORD'),
                                              )

        # mock. wait for ssh
        import bookshelf.api_v2.cloud
        bookshelf.api_v2.cloud.is_ssh_available = mock.Mock(return_value=True)

        srv = rackspace.create_server_rackspace(connection=conn,
                                                distribution='centos7',
                                                disk_name='disk',
                                                disk_size='75',
                                                ami='CentOS 7 (PVHVM)',
                                                region='IAD',
                                                key_pair='mykeypair',
                                                instance_type='1GB Standard Instance', # noqa
                                                instance_name='CentOS_7',
                                                tags={},
                                                security_groups=None)

        img = rackspace.create_rackspace_image(connection=conn,
                                               name='myImage',
                                               description='my Image',
                                               server_id=srv.id)

        self.assertRegexpMatches(img, '^.*-.*-.*-.*-*$')


class CreateServerRackspaceTests(unittest.TestCase):

    @vcr.use_cassette('fixtures/vcr_CreateServerRackspace.yml')
    def test_CreateServerRackspace(self,
                                   *args,
                                   **kwargs):

        conn = rackspace.connect_to_rackspace(os.environ.get('OS_REGION_NAME'),
                                              os.environ.get('OS_USERNAME'),
                                              os.environ.get('OS_PASSWORD'),
                                              )
        # mock. wait for ssh
        import bookshelf.api_v2.cloud
        bookshelf.api_v2.cloud.is_ssh_available = mock.Mock(return_value=True)

        srv = rackspace.create_server_rackspace(connection=conn,
                                                distribution='centos7',
                                                disk_name='disk',
                                                disk_size='75',
                                                ami='CentOS 7 (PVHVM)',
                                                region='IAD',
                                                key_pair='mykeypair',
                                                instance_type='1GB Standard Instance', # noqa
                                                instance_name='CentOS_7',
                                                tags={},
                                                security_groups=None)

        self.assertIsInstance(srv,
                              novaclient.v2.servers.Server)


class DestroyRackspaceTests(unittest.TestCase):

    @vcr.use_cassette('fixtures/vcr_DestroyRackspace.yml')
    def test_DestroyRackspace(self,
                              *args,
                              **kwargs):

        conn = rackspace.connect_to_rackspace(os.environ.get('OS_REGION_NAME'),
                                              os.environ.get('OS_USERNAME'),
                                              os.environ.get('OS_PASSWORD'),
                                              )

        # mock. wait for ssh
        import bookshelf.api_v2.cloud
        bookshelf.api_v2.cloud.is_ssh_available = mock.Mock(return_value=True)

        srv = rackspace.create_server_rackspace(connection=conn,
                                                distribution='centos7',
                                                disk_name='disk',
                                                disk_size='75',
                                                ami='CentOS 7 (PVHVM)',
                                                region='IAD',
                                                key_pair='mykeypair',
                                                instance_type='1GB Standard Instance',
                                                instance_name='CentOS_7',
                                                tags={},
                                                security_groups=None)

        rackspace.destroy_rackspace(connection=conn,
                                    region='IAD',
                                    instance_id=srv.id)


class DownRackspaceTests(unittest.TestCase):

    @vcr.use_cassette('fixtures/vcr_DownRackspace.yml')
    def test_DownRackspace(self,
                              *args,
                              **kwargs):

        conn = rackspace.connect_to_rackspace(os.environ.get('OS_REGION_NAME'),
                                              os.environ.get('OS_USERNAME'),
                                              os.environ.get('OS_PASSWORD'),
                                              )

        # mock. wait for ssh
        import bookshelf.api_v2.cloud
        bookshelf.api_v2.cloud.is_ssh_available = mock.Mock(return_value=True)

        srv = rackspace.create_server_rackspace(connection=conn,
                                                distribution='centos7',
                                                disk_name='disk',
                                                disk_size='75',
                                                ami='CentOS 7 (PVHVM)',
                                                region='IAD',
                                                key_pair='mykeypair',
                                                instance_type='1GB Standard Instance',
                                                instance_name='CentOS_7',
                                                tags={},
                                                security_groups=None)

        rackspace.destroy_rackspace(connection=conn,
                                    region='IAD',
                                    instance_id=srv.id)


class GetIpAddressFromRackspaceServerTests(unittest.TestCase):

    @vcr.use_cassette('fixtures/vcr_GetIpAddressFromRackspaceServer.yml')
    def test_GetIpAdressFromRackspaceServer(self,
                              *args,
                              **kwargs):

        conn = rackspace.connect_to_rackspace(os.environ.get('OS_REGION_NAME'),
                                              os.environ.get('OS_USERNAME'),
                                              os.environ.get('OS_PASSWORD'),
                                              )
        # mock. wait for ssh
        import bookshelf.api_v2.cloud
        bookshelf.api_v2.cloud.is_ssh_available = mock.Mock(return_value=True)

        srv = rackspace.create_server_rackspace(connection=conn,
                                                distribution='centos7',
                                                disk_name='disk',
                                                disk_size='75',
                                                ami='CentOS 7 (PVHVM)',
                                                region='IAD',
                                                key_pair='mykeypair',
                                                instance_type='1GB Standard Instance',
                                                instance_name='CentOS_7',
                                                tags={},
                                                security_groups=None)

        self.assertRegexpMatches(
            rackspace.get_ip_address_from_rackspace_server(connection=conn,
                                                           server_id=srv.id
                                                           ),
            '\d+\.\d+\.\d+\.\d+'
        )


class GetRackspaceInfoTests(unittest.TestCase):

    @vcr.use_cassette('fixtures/vcr_RackspaceInfo.yml')
    def test_RackspaceInfo(self,
                           *args,
                           **kwargs):

        def sortOD(od):
            res = OrderedDict()
            for k, v in sorted(od.items()):
                if isinstance(v, dict):
                    res[k] = sortOD(v)
                else:
                    res[k] = v
            return res

        conn = rackspace.connect_to_rackspace(os.environ.get('OS_REGION_NAME'),
                                              os.environ.get('OS_USERNAME'),
                                              os.environ.get('OS_PASSWORD'),
                                              )
        # mock. wait for ssh
        import bookshelf.api_v2.cloud
        bookshelf.api_v2.cloud.is_ssh_available = mock.Mock(return_value=True)

        srv = rackspace.create_server_rackspace(connection=conn,
                                                distribution='centos7',
                                                disk_name='disk',
                                                disk_size='75',
                                                ami='CentOS 7 (PVHVM)',
                                                region='IAD',
                                                key_pair='mykeypair',
                                                instance_type='1GB Standard Instance',
                                                instance_name='CentOS_7',
                                                tags={},
                                                security_groups=None)

        data = rackspace.get_rackspace_info(connection=conn,
                                            server_id=srv.id)

        expected_keys = [
            'ip_address',
            'accessIPv4',
            'accessIPv6',
            'addresses',
            'created',
            'flavor',
            'id',
            'human_id',
            'image',
            'key_name',
            'state',
            'metadata',
            'name',
            'networks',
            'tenant_id',
            'user_id',
            'cloud_type'
        ]


        for k in expected_keys:
            self.assertTrue(k in data)


if __name__ == '__main__':
    unittest.main()
