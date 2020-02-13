import pytest
import requests
import os
from markers import host_environment_test


FIRECREST_IP = os.environ.get("FIRECREST_IP")
if FIRECREST_IP:
	COMPUTE_URL = os.environ.get("FIRECREST_IP") + "/compute"
else:
    COMPUTE_URL = os.environ.get("COMPUTE_URL")	

JOBS_URL = COMPUTE_URL + "/jobs"
SERVER_COMPUTE = os.environ.get("SYSTEMS_PUBLIC").split(";")[0]


# test data: (server name, expected response code)
DATA = [ (SERVER_COMPUTE, 200) , ("someservernotavailable", 400)]


# Helper function for job submittings
def submit_job(machine, headers):
	files = {'file': ('upload.txt', open('testsbatch.sh', 'rb'))}
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(JOBS_URL, headers=headers, files=files)
	return resp


# Test send a job to the systems
@pytest.mark.parametrize("machine, expected_response_code", [ (SERVER_COMPUTE, 201) , ("someservernotavailable", 400)])
def test_submit_job(machine, expected_response_code, headers):
	resp = submit_job(machine, headers)
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test get all jobs from current user
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_list_jobs(machine, expected_response_code, headers):
	url = "{}".format(JOBS_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers)
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test Retrieve information from an active jobid (jobid in the queue or running)
@pytest.mark.parametrize("machine, expected_response_code",  DATA)
def test_list_job(machine, expected_response_code, headers):
	# TODO: need to test valid and invalid jobid
	jobid = -1
	url = "{}/{}".format(JOBS_URL, jobid)
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers)
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test cancel job from slurm
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_cancel_job(machine, expected_response_code, headers):
	# TODO: need to test valid and invalid jobid
	jobid = 1
	url = "{}/{}".format(JOBS_URL, jobid)
	headers.update({"X-Machine-Name": machine})
	resp = requests.delete(url, headers=headers)
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test get account information with sacct command
@pytest.mark.parametrize("machine, expected_response_code", DATA)
def test_acct(machine, expected_response_code, headers):
	url = "{}/acct".format(COMPUTE_URL)
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers)
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test get status of Jobs microservice
@host_environment_test
def test_status(headers):
	url = "{}/status".format(COMPUTE_URL)
	resp = requests.get(url, headers=headers)
	print(resp.content)
	assert resp.status_code == 200


if __name__ == '__main__':
	pytest.main()

