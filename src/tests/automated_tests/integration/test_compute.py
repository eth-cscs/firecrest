#
#  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import json
import pytest
import requests
import os
import time
from markers import skipif_not_uses_gateway

### SSL parameters
SSL_ENABLED = (os.environ.get("F7T_SSL_ENABLED","false").lower() == "true")
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_PATH = "../../../deploy/test-build"

FIRECREST_URL = os.environ.get("FIRECREST_URL")
if FIRECREST_URL:
	TASKS_URL = os.environ.get("FIRECREST_URL") + "/tasks"
	COMPUTE_URL = os.environ.get("FIRECREST_URL") + "/compute"
	UTILITIES_URL = os.environ.get("FIRECREST_URL") + "/utilities"
else:
	F7T_SCHEME_PROTOCOL = ("https" if SSL_ENABLED else "http")

	TASKS_HOST = os.environ.get("F7T_TASKS_HOST","127.0.0.1")
	TASKS_PORT = os.environ.get("F7T_TASKS_PORT","5003")
	TASKS_URL = f"{F7T_SCHEME_PROTOCOL}://{TASKS_HOST}:{TASKS_PORT}"

	COMPUTE_HOST = os.environ.get("F7T_COMPUTE_HOST","127.0.0.1")
	COMPUTE_PORT = os.environ.get("F7T_COMPUTE_PORT","5006")
	COMPUTE_URL = f"{F7T_SCHEME_PROTOCOL}://{COMPUTE_HOST}:{COMPUTE_PORT}"

	UTILITIES_HOST = os.environ.get("F7T_UTILITIES_HOST","127.0.0.1")
	UTILITIES_PORT = os.environ.get("F7T_UTILITIES_PORT","5004")
	UTILITIES_URL = f"{F7T_SCHEME_PROTOCOL}://{UTILITIES_HOST}:{UTILITIES_PORT}"

JOBS_URL = COMPUTE_URL + "/jobs"
SERVER_COMPUTE = os.environ.get("F7T_SYSTEMS_PUBLIC_NAME").strip('\'"').split(";")[0]

JOB_ENV = json.dumps({'F7T_TEST_JOB_ENV': 'a', 'F7T_TEST_JOB_ENV2': '"b 1"'})
JOB_ENV_OUTPUT = 'a\n"b 1"\n'




# Helper function for job submittings
def submit_job(machine, headers, file='testsbatch.sh'):
	files = {'file': ('upload.sh', open(file, 'rb'))}
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(f"{JOBS_URL}/upload", headers=headers, files=files, verify=False)
	print(resp.content)
	assert resp.status_code == 201
	return resp

def get_task(task_id, headers):
	url = f"{TASKS_URL}/{task_id}"
	resp = requests.get(url, headers=headers, verify=False)
	print(resp.content)
	assert resp.status_code == 200
	return resp

def check_task_status(task_id, headers, final_expected_status = 200): # may be 200, 300, 301, 400
	time.sleep(2) # make sure task is created??
	resp = get_task(task_id, headers)
	status = int(resp.json()["task"]["status"])
	assert status == 100 or status == 101 or status == final_expected_status

def get_job_id(task_id, headers):

	job_id = None
	for i in range(10):
		resp = get_task(task_id, headers)
		if "jobid" in resp.json()["task"]["data"]:
			if isinstance(resp.json()["task"]["data"]["jobid"], int):
				job_id = int(resp.json()["task"]["data"]["jobid"])
				break
		time.sleep(10)

	#assert "jobid" in resp.json()["task"]["data"]
	#job_id = int(resp.json()["task"]["data"]["jobid"])
	assert job_id is not None
	return job_id


# Test send a job to the system
@skipif_not_uses_gateway
@pytest.mark.parametrize("machine", [SERVER_COMPUTE])
def test_submit_job(machine, headers):
	resp = submit_job(machine, headers)
	task_id = resp.json()["task_id"]
	check_task_status(task_id, headers)

# Test get all jobs from current user
@skipif_not_uses_gateway
@pytest.mark.parametrize("machine", [SERVER_COMPUTE])
def test_list_jobs(machine, headers):
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(JOBS_URL, headers=headers, verify=False)
	print(resp.content)
	assert resp.status_code == 200

	task_id = resp.json()["task_id"]
	check_task_status(task_id, headers)

# Test Retrieve information from an invalid jobid (jobid in the queue or running)
@skipif_not_uses_gateway
@pytest.mark.parametrize("machine", [SERVER_COMPUTE])
def test_list_job(machine, headers):
	jobid = -1
	url = f"{JOBS_URL}/{jobid}"
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, verify=False)
	print(resp.content)
	assert resp.status_code == 400
	# task_id = resp.json()["task_id"]
	# check_task_status(task_id, headers, 400)

# Test cancel job from slurm
@skipif_not_uses_gateway
@pytest.mark.parametrize("machine", [SERVER_COMPUTE])
def test_cancel_job(machine, headers):

	resp = submit_job(machine, headers)
	task_id = resp.json()["task_id"]
	job_id = get_job_id(task_id, headers)

	# cancel job
	url = f"{JOBS_URL}/{job_id}"
	headers.update({"X-Machine-Name": machine})
	resp = requests.delete(url, headers=headers, verify=False)
	print(resp.content)
	assert resp.status_code == 200

	# check scancel status
	task_id = resp.json()["task_id"]
	check_task_status(resp.json()["task_id"],headers)

# Test account information
@skipif_not_uses_gateway
@pytest.mark.parametrize("machine", [SERVER_COMPUTE])
def test_acct_job(machine, headers):

	resp = submit_job(machine, headers)
	task_id = resp.json()["task_id"]
	job_id = get_job_id(task_id, headers)

	# cancel job
	url = f"{COMPUTE_URL}/acct"
	params = {"jobs": job_id}
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers,params=params, verify=False)
	print(resp.content)
	assert resp.status_code == 200

	# check scancel status
	task_id = resp.json()["task_id"]
	check_task_status(resp.json()["task_id"],headers)

	# cancel all previous jobs
	lj = "1"
	for i in range(2, job_id):
		lj += "," + str(i)
	url = f"{JOBS_URL}/{lj}"
	resp = requests.delete(url, headers=headers, verify=False)
	print(resp.content)
	assert resp.status_code == 200

# Test job enviroment variables
@skipif_not_uses_gateway
def test_job_env(headers):
	headers.update({"X-Machine-Name": SERVER_COMPUTE})
	data = {"env" : JOB_ENV}
	files = {"file": ('upload.sh', open('testsbatch.sh', 'rb'))}
	resp = requests.post(f"{JOBS_URL}/upload", headers=headers, data=data, files=files, verify=False)
	assert resp.status_code == 201
	task_id = resp.json()["task_id"]
	job_id = get_job_id(task_id, headers)
	params = {"targetPath": f"/tmp/env_{job_id}.out"}
	url = f"{UTILITIES_URL}/ls"
	for i in range(10):
		time.sleep(5)
		resp = requests.get(url, headers=headers, params=params, verify=False)
		if resp.status_code == 200:
			break
	url = f"{UTILITIES_URL}/head"
	resp = requests.get(url, headers=headers, params=params, verify=False)
	assert resp.status_code == 200
	assert json.loads(resp.content)["output"] == JOB_ENV_OUTPUT


# Test nodes information
@skipif_not_uses_gateway
@pytest.mark.parametrize("machine", [SERVER_COMPUTE])
def test_nodes(machine, headers):
	url = f"{COMPUTE_URL}/nodes"
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, verify=False)
	print(resp.content)
	assert resp.status_code == 200

	# check scancel status
	task_id = resp.json()["task_id"]
	check_task_status(task_id, headers)


# Test partitions information
@skipif_not_uses_gateway
@pytest.mark.parametrize("machine", [SERVER_COMPUTE])
def test_partitions(machine, headers):
	url = f"{COMPUTE_URL}/partitions"
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, verify=False)
	print(resp.content)
	assert resp.status_code == 200

	# check scancel status
	task_id = resp.json()["task_id"]
	check_task_status(task_id, headers)


@skipif_not_uses_gateway
@pytest.mark.parametrize("machine", [SERVER_COMPUTE])
def test_partitions_xfer(machine, headers):
	url = f"{COMPUTE_URL}/partitions"
	headers.update({"X-Machine-Name": machine})
	params = {"partitions": "xfer"}
	resp = requests.get(url, headers=headers, params=params, verify=False)
	print(resp.content)
	assert resp.status_code == 200

	# check scancel status
	task_id = resp.json()["task_id"]
	check_task_status(task_id, headers)


if __name__ == '__main__':
	pytest.main()


