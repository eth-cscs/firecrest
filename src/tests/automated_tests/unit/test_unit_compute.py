#
#  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import pytest
import requests
import os
from markers import skipif_uses_gateway, skipif_not_uses_gateway
from test_globals import *

FIRECREST_URL = os.environ.get("FIRECREST_URL")
USE_GATEWAY  = (os.environ.get("USE_GATEWAY","false").lower() == "true")
if FIRECREST_URL and USE_GATEWAY:
	COMPUTE_URL = os.environ.get("FIRECREST_URL") + "/compute"
else:
    COMPUTE_URL = os.environ.get("F7T_COMPUTE_URL")

JOBS_URL = COMPUTE_URL + "/jobs"
SERVER_COMPUTE = os.environ.get("F7T_SYSTEMS_PUBLIC").strip('\'"').split(";")[0]

### SSL parameters
USE_SSL = os.environ.get("F7T_USE_SSL", False)
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_PATH = "../../../deploy/test-build"


# test data: (server name, expected response code)
DATA = [ (SERVER_COMPUTE, 200) , ("someservernotavailable", 400)]


# Helper function for job submittings
def submit_job_upload(machine, headers):
	print(f"COMPUTE_URL {COMPUTE_URL}")
	files = {'file': ('upload.txt', open('testsbatch.sh', 'rb'))}
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(f"{JOBS_URL}/upload", headers=headers, files=files, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	return resp

# Helper function for job submittings with accounts
def submit_job_upload_account(machine, account, headers):
	print(f"COMPUTE_URL {COMPUTE_URL}")
	files = {'file': ('upload.txt', open('testsbatch.sh', 'rb'))}
	data = {"account":account}
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(f"{JOBS_URL}/upload", headers=headers, data=data, files=files, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	return resp


# Test send a job to the systems
@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code", [ (SERVER_COMPUTE, 201) , ("someservernotavailable", 400)])
def test_submit_job_upload(machine, expected_response_code, headers):
	resp = submit_job_upload(machine, headers)
	print(resp.content)
	assert resp.status_code == expected_response_code

@pytest.mark.parametrize("machine, account, expected_response_code", [
	(SERVER_COMPUTE, "test", 201) ,
	(SERVER_COMPUTE, None, 201),
	(SERVER_COMPUTE, "", 400),
	])
def test_submit_job_upload_account(machine, account, expected_response_code, headers):
	resp = submit_job_upload_account(machine, account, headers)
	print(resp.content)
	assert resp.status_code == expected_response_code

# Test send a job to the systems
@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, targetPath, expected_response_code", [
	(SERVER_COMPUTE, "/srv/f7t/test_sbatch.sh", 201),
(SERVER_COMPUTE, "/srv/f7t/test_sbatch.sh", 201),
	(SERVER_COMPUTE, "/srv/f7t/test_sbatch.sh", 201),
(SERVER_COMPUTE, "/srv/f7t/test_sbatch.sh", 201),
	(SERVER_COMPUTE, "/srv/f7t/test_sbatch.sh", 201),
	(SERVER_COMPUTE, "/srv/f7t/test_sbatch_forbidden.sh", 400),
	(SERVER_COMPUTE, "/srv/f7t", 400),
	(SERVER_COMPUTE, "notexists", 400),
	(SERVER_COMPUTE, "", 400),
	(SERVER_COMPUTE, None, 400),
	("someservernotavailable", "/srv/f7t/test_sbatch.sh", 400)]

)
def test_submit_job_path(machine, targetPath, expected_response_code, headers):
	data = {"targetPath" : targetPath}
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(f"{JOBS_URL}/path", headers=headers, data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	print(resp.headers)
	assert resp.status_code == expected_response_code

@pytest.mark.parametrize("machine, targetPath, account, expected_response_code", [
	(SERVER_COMPUTE, "/srv/f7t/test_sbatch.sh", "test", 201),
	(SERVER_COMPUTE, "/srv/f7t/test_sbatch.sh", None, 201),
	(SERVER_COMPUTE, "/srv/f7t/test_sbatch.sh", "", 400),
	] )
def test_submit_job_path_account(machine, targetPath, account, expected_response_code, headers):
	data = {"targetPath" : targetPath, "account": account}
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(f"{JOBS_URL}/path", headers=headers, data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	print(resp.headers)
	assert resp.status_code == expected_response_code


# Test get all jobs from current user
@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_list_jobs(machine, expected_response_code, headers):
	url = f"{JOBS_URL}"
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test Retrieve information from an active jobid (jobid in the queue or running)
@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code",  [ (SERVER_COMPUTE, 400) , ("someservernotavailable", 400)])
def test_list_job(machine, expected_response_code, headers):
	# TODO: need to test valid
	jobid = -1
	url = f"{JOBS_URL}/{jobid}"
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test cancel job from slurm
@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_cancel_job(machine, expected_response_code, headers):
	# TODO: need to test valid and invalid jobid
	jobid = 1
	url = f"{JOBS_URL}/{jobid}"
	headers.update({"X-Machine-Name": machine})
	resp = requests.delete(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test get account information with sacct command
@skipif_not_uses_gateway
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_acct(machine, expected_response_code, headers):
	jobid = "2,3"
	url = f"{COMPUTE_URL}/acct"
	headers.update({"X-Machine-Name": machine})
	params = {"jobs":jobid}
	resp = requests.get(url, headers=headers, params=params, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test get status of Jobs microservice
@skipif_uses_gateway
def test_status(headers):
	url = f"{COMPUTE_URL}/status"
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == 200


if __name__ == '__main__':
	pytest.main()

