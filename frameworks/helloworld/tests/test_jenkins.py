import logging
import re
import uuid

import dcos.marathon
import pytest
import retrying
import sdk_cmd
import sdk_install
import sdk_marathon
import sdk_plan
import sdk_tasks
import sdk_upgrade
import sdk_utils
import shakedown
from tests import config
from tests import jenkins


log = logging.getLogger(__name__)

service_name = 'jenkins'


@pytest.mark.sanity
def test_get_builds():
    log.info('Getting Jenkins jobs')
    jobs = jenkins.get_jobs(service_name)
    log.info('jobs: {}'.format(jobs))

    for job in jobs:
        name = job['name']
        log.info('first build: {}'.format(jenkins.get_first_build(service_name, name)))
        log.info('last build: {}'.format(jenkins.get_last_build(service_name, name)))


@pytest.mark.sanity
def test_copy_job():
    for x in range(0, 100):
        copy_name = str(uuid.uuid4())
        jenkins.copy_job(service_name, 'kvish-test2', copy_name)
