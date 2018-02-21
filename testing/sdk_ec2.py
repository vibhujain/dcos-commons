import logging

import boto3
import botocore
import os
import time
import uuid

LOG = logging.getLogger(__name__)


class EC2Partitioner:
    def __init__(self, private_ip: str):
        LOG.info("Instantiating partitioner using private_ip %s", private_ip)

        # Look up the instance
        ec2 = boto3.resource('ec2')
        self.instance = list(ec2.instances.filter(Filters=[
            {
                "Name": "private-ip-address",
                "Values": [private_ip]
            }
        ]))[0]

        self.partitioned = False
        self.old_security_groups = []
        self.partitioner_ssh_group = None


    def partition(self):
        LOG.info("Partitioning the instance...")

        if self.partitioned:
            LOG.info("This instance is already partitioned.")
            return

        # Update the stored instance
        self.instance.load()

        # Retrieve the current security group ids.
        self.old_security_groups = [sg["GroupId"] for sg in self.instance.security_groups]
        LOG.info("Before the partition, the instance has security groups %s", self.old_security_groups)

        # Make sure the ssh security group exists
        self.partitioner_ssh_group = self._create_ssh_security_group(self.instance.vpc_id)

        self.instance.modify_attribute(Groups=[self.partitioner_ssh_group.group_id])

        self.partitioned = True
        LOG.info("Instance partitioned.")


    def heal_partition(self):
        LOG.info("Healing the instance's partition")

        if not self.partitioned:
            LOG.info("This instance is not partitioned.")
            return

        # Update the stored instance
        self.instance.load()

        # Reset the security groups to the old values
        self.instance.modify_attribute(Groups=self.old_security_groups)
        # Delete the adhoc ssh group
        self.partitioner_ssh_group.delete()

        self.partitioned = False
        LOG.info("Partition healed")


    def _create_ssh_security_group(self, vpc_id: str):
        LOG.info("Creating PartitionerSSHGroup security group and opening port 22")
        ec2 = boto3.resource('ec2')
        vpc = ec2.Vpc(vpc_id)

        ssh_group = vpc.create_security_group(
            Description="This security group is used when removing security groups to make sure SSH is left open",
            GroupName="PartitionerSSHGroup" + str(uuid.uuid4()),
        )

        LOG.info("Created PartitionerSSHGroup with id %s", ssh_group.group_id)

        LOG.info("Creating an ingress rule for port 22 from 0.0.0.0/0")
        ssh_group.authorize_ingress(
            CidrIp="0.0.0.0/0",
            FromPort=22,
            ToPort=22,
            IpProtocol='tcp'
        )

        LOG.info("PartitionerSSHGroup created.")
        return ssh_group
