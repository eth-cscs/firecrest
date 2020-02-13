import pytest
import requests
import os
import time


FIRECREST_IP = os.environ.get("FIRECREST_IP")
if FIRECREST_IP:
	TASKS_URL = os.environ.get("FIRECREST_IP") + "/tasks"
	COMPUTE_URL = os.environ.get("FIRECREST_IP") + "/compute"
else:
	TASKS_URL = os.environ.get("TASKS_URL")
	COMPUTE_URL = os.environ.get("COMPUTE_URL")

JOBS_URL = COMPUTE_URL + "/jobs"
SERVER_COMPUTE = os.environ.get("SYSTEMS_PUBLIC").split(";")[0]



# Helper function for job submittings
def submit_job(machine, headers, file='testsbatch.sh'):
	files = {'file': ('upload.txt', open(file, 'rb'))}
	headers.update({"X-Machine-Name": machine})
	resp = requests.post(JOBS_URL, headers=headers, files=files)
	print(resp.content)
	assert resp.status_code == 201
	return resp

def get_task(task_id, headers):
	url = "{}/{}".format(TASKS_URL, task_id)
	resp = requests.get(url, headers=headers)
	print(resp.content)
	assert resp.status_code == 200
	return resp

def check_task_status(task_id, headers, final_expected_status = 200): # may be 200, 300, 301, 400
	time.sleep(2) # make sure task is created??
	resp = get_task(task_id, headers)
	status = int(resp.json()["task"]["status"])
	assert status == 100 or status == 101 or status == final_expected_status

def get_job_id(task_id, headers):
	resp = get_task(task_id, headers)
	assert "jobid" in resp.json()["task"]["data"]
	job_id = int(resp.json()["task"]["data"]["jobid"])
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
	resp = requests.get(JOBS_URL, headers=headers)
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
	resp = requests.get(url, headers=headers)
	print(resp.content)
	assert resp.status_code == 200
	task_id = resp.json()["task_id"]
	check_task_status(task_id, headers, 400)

# Test cancel job from slurm
@pytest.mark.parametrize("machine", [SERVER_COMPUTE])
def test_cancel_job(machine, headers):

	resp = submit_job(machine, headers)
	task_id = resp.json()["task_id"]

	time.sleep(10) # wait until task is runnig
	job_id = get_job_id(task_id, headers)

	# cancel job
	url = "{}/{}".format(JOBS_URL, job_id)
	headers.update({"X-Machine-Name": machine})
	resp = requests.delete(url, headers=headers)
	print(resp.content)
	assert resp.status_code == 200

	# check scancel status
	task_id = resp.json()["task_id"]
	check_task_status(resp.json()["task_id"],headers)

if __name__ == '__main__':
	pytest.main()	


