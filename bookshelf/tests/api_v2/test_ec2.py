import unittest
import boto
from bookshelf.api_v2 import ec2
from moto import mock_ec2


class ConnectToEc2Tests(unittest.TestCase):

    @mock_ec2
    def test_connect_to_ec2_returns_connection_object(self, *args, **kwargs):
        conn = ec2.connect_to_ec2('us-west-2', 'ACESSKEY', 'SECRETKEY')
        self.assertTrue(isinstance(conn, boto.ec2.connection.EC2Connection))

    @mock_ec2
    def test_add_user_local_bin_returns_False_on_failure(self, *args, **kwargs):
        self.assertFalse(ec2.connect_to_ec2('fake-region',
                                            'ACESSKEY',
                                            'SECRETKEY'))


class CreateAmiTests(unittest.TestCase):

    @mock_ec2
    def test_create_ami_returns_ami(self, *args, **kwargs):
        conn = boto.connect_ec2('the_key', 'the_secret')
        reservation = conn.run_instances('ami-1234abcd')
        instance = reservation.instances[0]
        ami = ec2.create_ami(connection=conn,
                             region='us-west-2',
                             access_key_id='access_key_id',
                             secret_access_key='SECRETKEY',
                             instance_id=instance.id,
                             name='my-new-ami',
                             description='mynewami',
                             block_device_mapping='rubbish')
        self.assertRegexpMatches(ami, '^ami-[0-f]*$')

    @mock_ec2
    def test_create_ami_raises_Exception_on_failure(self, *args, **kwargs):
        conn = boto.connect_ec2('the_key', 'the_secret')

        self.failUnlessRaises(Exception,
                              ec2.create_ami,
                              connection=conn,
                              region='us-west-2',
                              access_key_id='access_key_id',
                              secret_access_key='SECRETKEY',
                              instance_id='fake-id',
                              name='my-new-ami',
                              description='mynewami',
                              block_device_mapping='rubbish')


class CreateServerEC2Tests(unittest.TestCase):

    @mock_ec2
    def test_create_server_ec2_returns_instance_object(self, *args, **kwargs):
        conn = boto.connect_ec2('the_key', 'the_secret')
        reservation = conn.run_instances('ami-1234abcd')
        instance = reservation.instances[0]
        image_id = conn.create_image(instance.id,
                                     "test-ami",
                                     "this is a test ami")
        conn.create_key_pair('foo')

        instance = ec2.create_server_ec2(connection=conn,
                                         region='us-west-2',
                                         access_key_id='access_key_id',
                                         secret_access_key='SECRETKEY',
                                         disk_name='/dev/sda',
                                         disk_size=16,
                                         ami=image_id,
                                         key_pair='foo',
                                         instance_type='t2.micro',
                                         tags={'Name': 'test'},
                                         wait_for_ssh_available=False)

        self.assertTrue(isinstance(instance, boto.ec2.instance.Instance))

    @mock_ec2
    def test_create_ami_raises_Exception_on_failure(self, *args, **kwargs):
        conn = boto.connect_ec2('the_key', 'the_secret')

        self.failUnlessRaises(Exception,
                              ec2.create_server_ec2,
                              connection=conn,
                              region='us-west-2',
                              access_key_id='access_key_id',
                              secret_access_key='SECRETKEY',
                              disk_name='/dev/sda',
                              disk_size=16,
                              ami='ami-nonvalid',
                              key_pair='non-valid-keypair',
                              instance_type='t2.micro',
                              tags={'Name': 'test'},
                              wait_for_ssh_available=False)


class DestroyEBSVolumeTests(unittest.TestCase):

    @mock_ec2
    def test_destroy_ebs_volume_destroys_volume(self, *args, **kwargs):
        conn = boto.connect_ec2('the_key', 'the_secret')
        volume = conn.create_volume(80, "us-east-1a")

        ec2.destroy_ebs_volume(connection=conn,
                               region='us-west-2',
                               volume_id=volume.id)

        all_volumes = conn.get_all_volumes()
        self.assertEquals(len(all_volumes), 0)


class DestroyEC2Tests(unittest.TestCase):

    @mock_ec2
    def test_destroy_ec2_destroys_instance(self, *args, **kwargs):
        conn = boto.connect_ec2('the_key', 'the_secret')
        reservation = conn.run_instances('ami-1234abcd')
        instance = reservation.instances[0]

        ec2.destroy_ec2(connection=conn,
                        region='us-west-2',
                        instance_id=instance.id)

        reservations = conn.get_all_instances()
        instance = reservations[0].instances[0]
        self.assertEquals(instance.state, 'terminated')

    @mock_ec2
    def test_destroy_ec2_raises_Exception_on_failure(self, *args, **kwargs):
        conn = boto.connect_ec2('the_key', 'the_secret')

        self.failUnlessRaises(Exception,
                              ec2.destroy_ec2,
                              connection=conn,
                              region='us-west-2',
                              instance_id='fake')


class DownEC2Tests(unittest.TestCase):

    @mock_ec2
    def test_down_ec2_stops_instance(self, *args, **kwargs):
        conn = boto.connect_ec2('the_key', 'the_secret')
        reservation = conn.run_instances('ami-1234abcd')
        instance = reservation.instances[0]

        ec2.down_ec2(connection=conn,
                     region='us-west-2',
                     instance_id=instance.id)

        reservations = conn.get_all_instances()
        instance = reservations[0].instances[0]
        self.assertEquals(instance.state, 'stopped')

    @mock_ec2
    def test_down_ec2_raises_Exception_on_failure(self, *args, **kwargs):
        conn = boto.connect_ec2('the_key', 'the_secret')

        self.failUnlessRaises(Exception,
                              ec2.down_ec2,
                              connection=conn,
                              region='us-west-2',
                              instance_id='fake')


class EBSVolumeExistsTests(unittest.TestCase):

    @mock_ec2
    def test_ebs_volume_exists_returns_True(self, *args, **kwargs):
        conn = boto.connect_ec2('the_key', 'the_secret')
        volume = conn.create_volume(80, "us-east-1a")

        self.assertTrue(
            ec2.ebs_volume_exists(connection=conn,
                                  region='us-west-2',
                                  volume_id=volume.id)
        )

    @mock_ec2
    def test_ebs_volume_exists_returns_False(self, *args, **kwargs):
        conn = boto.connect_ec2('the_key', 'the_secret')

        self.assertFalse(
            ec2.ebs_volume_exists(connection=conn,
                                  region='us-west-2',
                                  volume_id='fake-volume')
        )


class GetEC2InfoTests(unittest.TestCase):

    @mock_ec2
    def test_gets_ec2_info_returns_dictionary(self, *args, **kwargs):
        conn = boto.connect_ec2('the_key', 'the_secret')
        reservation = conn.run_instances('ami-1234abcd')
        instance = reservation.instances[0]

        data = ec2.get_ec2_info(connection=conn,
                                instance_id=instance.id,
                                region='us-west-2')

        expected_keys = [
            '_state',
            'ami_launch_index',
            'architecture',
            'block_device_mapping',
            'client_token',
            'connection',
            'dns_name',
            'eventsSet',
            'group_name',
            'groups',
            'hypervisor',
            'id',
            'image_id',
            'instance_profile',
            'instance_type',
            'interfaces',
            'ip_address',
            'item',
            'kernel',
            'key_name',
            'launch_time',
            'monitored',
            'monitoring',
            'monitoring_state',
            'persistent',
            'platform',
            'private_dns_name',
            'private_ip_address',
            'product_codes',
            'public_dns_name',
            'ramdisk',
            'reason',
            'region',
            'requester_id',
            'root_device_name',
            'root_device_name',
            'root_device_type',
            'sourceDestCheck',
            'spot_instance_request_id',
            'state',
            'state_reason',
            'subnet_id',
            'tags',
            'virtualization_type',
            'volume',
            'vpc_id',
        ]

        for k in expected_keys:
            self.assertTrue(k in data)


class UpEC2Tests(unittest.TestCase):

    @mock_ec2
    def test_up_ec2_starts_existing_instance(self, *args, **kwargs):
        conn = boto.connect_ec2('the_key', 'the_secret')
        reservation = conn.run_instances('ami-1234abcd')
        instance = reservation.instances[0]

        ec2.up_ec2(connection=conn,
                   instance_id=instance.id,
                   region='us-west-2',
                   wait_for_ssh_available=False)

        instance.update()

        self.assertEquals(instance.state, 'running')


if __name__ == '__main__':
    unittest.main()
