import pytest
import requests
import os
import time
import json
import io


FIRECREST_URL = os.environ.get("FIRECREST_URL")
if FIRECREST_URL:
	TASKS_URL = os.environ.get("FIRECREST_URL") + "/tasks"
	COMPUTE_URL = os.environ.get("FIRECREST_URL") + "/compute"
else:
	TASKS_URL = os.environ.get("F7T_TASKS_URL")
	COMPUTE_URL = os.environ.get("F7T_COMPUTE_URL")

JOBS_URL = COMPUTE_URL + "/jobs"
SERVER_COMPUTE = os.environ.get("F7T_SYSTEMS_PUBLIC").split(";")[0]



# Helper function for job submittings
def submit_job(machine, headers, file='testsbatch.sh'):
	#files = {'file': ('upload.txt', open(file, 'rb'))}

	s = '#!/bin/bash\n#SBATCH --job-name=testsbatch\n#SBATCH --ntasks=1\n#SBATCH --tasks-per-node=1\n#SBATCH --output=testsbatch.output\n#SBATCH --error=testsbatch.error\nsleep 700s'

	files = {'file': ('upload.txt', s)}

	headers.update({"X-Machine-Name": machine})
	resp = requests.post(JOBS_URL, headers=headers, files=files, timeout=(27, 27))
	#print(json.dumps(resp.json(),indent=2))
	assert resp.status_code == 201
	return resp

def get_task(task_id, headers):
	url = "{}/{}".format(TASKS_URL, task_id)
	resp = requests.get(url, headers=headers, timeout=(27, 27))
	#print(json.dumps(resp.json(),indent=2))
	assert resp.status_code == 200
	return resp

def check_task_status(task_id, headers, final_expected_status = 200): # may be 200, 300, 301, 400
	time.sleep(2) # make sure task is created??
	resp = get_task(task_id, headers)
	status = int(resp.json()["task"]["status"])
	print(json.dumps(resp.json(),indent=2))
	assert status == 100 or status == 101 or status == final_expected_status



# Test send a job to the system
@pytest.mark.parametrize("sid", range(1, 51))
def test_submit_job(sid, headers):
	resp = submit_job(SERVER_COMPUTE, headers)
	task_id = resp.json()["task_id"]
	check_task_status(task_id, headers)

