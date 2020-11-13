import pytest
import requests
import os
import time


FIRECREST_URL = os.environ.get("FIRECREST_URL")
if FIRECREST_URL:
	TASKS_URL = os.environ.get("FIRECREST_URL") + "/tasks"
	COMPUTE_URL = os.environ.get("FIRECREST_URL") + "/compute"
else:
	TASKS_URL = os.environ.get("F7T_TASKS_URL")
	COMPUTE_URL = os.environ.get("F7T_COMPUTE_URL")

JOBS_URL = COMPUTE_URL + "/jobs"
SERVER_COMPUTE = os.environ.get("F7T_SYSTEMS_PUBLIC").split(";")[0]

### SSL parameters
USE_SSL = os.environ.get("F7T_USE_SSL", False)
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_PATH = "../../../deploy/test-build"


# Helper function for job submittings
def submit_job(machine, headers, file='testsbatch.sh'):
	files = {'file': ('upload.txt', open(file, 'rb'))}
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(f"{JOBS_URL}/upload", headers=headers, files=files, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == 201
	return resp

def get_task(task_id, headers):
	url = "{}/{}".format(TASKS_URL, task_id)
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
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
@pytest.mark.parametrize("machine", [SERVER_COMPUTE])
def test_submit_job(machine, headers):
	resp = submit_job(machine, headers)
	task_id = resp.json()["task_id"]
	check_task_status(task_id, headers)

# Test get all jobs from current user
@pytest.mark.parametrize("machine", [SERVER_COMPUTE])
def test_list_jobs(machine, headers):
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(JOBS_URL, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == 200
	
	task_id = resp.json()["task_id"]
	check_task_status(task_id, headers)

# Test Retrieve information from an invalid jobid (jobid in the queue or running)
@pytest.mark.parametrize("machine",  [SERVER_COMPUTE])
def test_list_job(machine, headers):
	jobid = -1
	url = "{}/{}".format(JOBS_URL, jobid)
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == 400
	# task_id = resp.json()["task_id"]
	# check_task_status(task_id, headers, 400)

# Test cancel job from slurm
@pytest.mark.parametrize("machine", [SERVER_COMPUTE])
def test_cancel_job(machine, headers):

	resp = submit_job(machine, headers)
	task_id = resp.json()["task_id"]
	job_id = get_job_id(task_id, headers)
		
	# cancel job
	url = "{}/{}".format(JOBS_URL, job_id)
	headers.update({"X-Machine-Name": machine})
	resp = requests.delete(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == 200

	# check scancel status
	task_id = resp.json()["task_id"]
	check_task_status(resp.json()["task_id"],headers)

# Test account information
@pytest.mark.parametrize("machine", [SERVER_COMPUTE])
def test_acct_job(machine, headers):

	resp = submit_job(machine, headers)
	task_id = resp.json()["task_id"]
	job_id = get_job_id(task_id, headers)

	# cancel job
	url = "{}/acct".format(COMPUTE_URL)
	params = {"jobs": job_id}
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers,params=params, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == 200

	# check scancel status
	task_id = resp.json()["task_id"]
	check_task_status(resp.json()["task_id"],headers)

if __name__ == '__main__':
	pytest.main()	


