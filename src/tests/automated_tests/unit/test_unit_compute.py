import pytest
import requests
import os
from markers import host_environment_test
from test_globals import *

FIRECREST_URL = os.environ.get("FIRECREST_URL")
if FIRECREST_URL:
	COMPUTE_URL = os.environ.get("FIRECREST_URL") + "/compute"
else:
    COMPUTE_URL = os.environ.get("F7T_COMPUTE_URL")	

JOBS_URL = COMPUTE_URL + "/jobs"
SERVER_COMPUTE = os.environ.get("F7T_SYSTEMS_PUBLIC").split(";")[0]

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


# Test send a job to the systems
@pytest.mark.parametrize("machine, expected_response_code", [ (SERVER_COMPUTE, 201) , ("someservernotavailable", 400)])
def test_submit_job_upload(machine, expected_response_code, headers):
	resp = submit_job_upload(machine, headers)
	print(resp.content)
	assert resp.status_code == expected_response_code

# Test send a job to the systems
@pytest.mark.parametrize("machine, targetPath, expected_response_code", [ 
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


# Test get all jobs from current user
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_list_jobs(machine, expected_response_code, headers):
	url = "{}".format(JOBS_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test Retrieve information from an active jobid (jobid in the queue or running)
@pytest.mark.parametrize("machine, expected_response_code",  [ (SERVER_COMPUTE, 400) , ("someservernotavailable", 400)])
def test_list_job(machine, expected_response_code, headers):
	# TODO: need to test valid
	jobid = -1
	url = "{}/{}".format(JOBS_URL, jobid)
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test cancel job from slurm
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_cancel_job(machine, expected_response_code, headers):
	# TODO: need to test valid and invalid jobid
	jobid = 1
	url = "{}/{}".format(JOBS_URL, jobid)
	headers.update({"X-Machine-Name": machine})
	resp = requests.delete(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test get account information with sacct command
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_acct(machine, expected_response_code, headers):
	jobid = "2,3"
	url = "{}/acct".format(COMPUTE_URL)
	headers.update({"X-Machine-Name": machine})
	params = {"jobs":jobid}
	resp = requests.get(url, headers=headers, params=params, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test get status of Jobs microservice
@host_environment_test
def test_status(headers):
	url = "{}/status".format(COMPUTE_URL)
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == 200


if __name__ == '__main__':
	pytest.main()

