import pytest
import requests
import os
from test_globals import *
from markers import *

from pytest_cases import parametrize_plus, fixture_plus, fixture_ref

FIRECREST_URL = os.environ.get("FIRECREST_URL")
if FIRECREST_URL:
	COMPUTE_URL = os.environ.get("FIRECREST_URL") + "/compute"
else:
    COMPUTE_URL = os.environ.get("F7T_COMPUTE_URL")	

JOBS_URL = COMPUTE_URL + "/jobs"
SERVER_COMPUTE = os.environ.get("F7T_SYSTEMS_PUBLIC").split(";")[0]


# Helper function for job submitting
def submit_job(machine, files, headers):
	if isinstance(headers,dict):
		headers.update({"X-Machine-Name": machine})
	resp = requests.post(JOBS_URL, headers=headers, files=files)
	return resp


# Test job submission to systems
@parametrize_plus("machine, filename, expected_response_code, headers", 
[ 

# 1 - valid headers dict
(SERVER_COMPUTE, 'sample', 201, fixture_ref(headers)) ,

# 2 - unknown machine name
("someservernotavailable", 'sample', 400, fixture_ref(headers)),

# 3 - no machine name
('', 'sample', 400, fixture_ref(headers)),

# 4 - empty headers dict
(SERVER_COMPUTE, 'sample', 401, {}),

# 5 - no auth header
(SERVER_COMPUTE, 'sample', 401, fixture_ref(headers_no_auth)),

# 6 - invalid auth header (for demo environment)
pytest.param(SERVER_COMPUTE, 'sample', 401, fixture_ref(headers_invalid_auth), marks=demo_environment_test),

# 7 - file not specified
(SERVER_COMPUTE, '', 400, fixture_ref(headers)),

# 8 - empty file
(SERVER_COMPUTE, 'empty', 400, fixture_ref(headers)),

# 9 - zero bytes file
(SERVER_COMPUTE, 'zerobytes', 201, fixture_ref(headers)),

# 10 - file size greater than max size allowed: in test-build environment RequestEntityTooLarge(413) exception is not handled by request_entity_too_large: client is disconnected by flask -> Connection aborted, BrokenPipeError                  
pytest.param(SERVER_COMPUTE, 'sample_big', 413, fixture_ref(headers), marks=demo_environment_test)

])
def test_submit_job(machine, filename, expected_response_code, headers, tmpdir):
	
	files = {'file': None}

	if filename=='zerobytes':
		files = {'file': ('upload', '')}

	if filename=='empty':
		files = {'file': None}

	if filename=='':
		files = {}
	
	if filename=='sample':
		sample = '#!/bin/bash\n#SBATCH --job-name=testsbatch\n#SBATCH --ntasks=1\n#SBATCH --tasks-per-node=1\n#SBATCH --output=testsbatch.output\n#SBATCH --error=testsbatch.error\nsleep 700s'
		files = {'file': ('upload', sample)} # firecrest searchs for "file" file
	
	if filename=='sample_big':

		# strange behavior: for getting 201, file size should not be greater than (MAX_FILE_SIZE - 200) bytes
		size = int(os.environ.get("F7T_UTILITIES_MAX_FILE_SIZE")) * 1024 * 1024 
		bigFile = tmpdir.join("bigFile")
		f = bigFile.open(mode='w+b', ensure=False, encoding=None)
		f.write(os.urandom(size))
		f.close()
		
		files = {'file': ('upload', bigFile.open(mode='rb', ensure=True, encoding=None))}
		#print("bigFile desired size: " +  str(size))
		#print("bigFile size: " +  str(os.path.getsize(bigFile)))
		#print("Max upload size is {}".format(os.environ.get("F7T_UTILITIES_MAX_FILE_SIZE")))

	resp = submit_job(machine, files, headers)
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test get all jobs from current user
@pytest.mark.parametrize("machine, expected_response_code, jobs",

[ 

# 1 - valid list jobs query
(SERVER_COMPUTE, 200, None) , 

# 2- unknown server
("someservernotavailable", 400, None),

# 3 -no machine name specified
("", 400, None),

# 4 -valid job id list
(SERVER_COMPUTE, 200, "1500,500"),

# 5 - invalid job id list: malformed comma separated string value
(SERVER_COMPUTE, 400, "1500,"),

# 6 - invalid job id list: empty job id
(SERVER_COMPUTE, 400, ""),

# 7 - invalid job id list: empty job ids
(SERVER_COMPUTE, 400, ","),

# TODO: should we test jobs list validation?
# 8 - invalid job id list: not numeric job ids
(SERVER_COMPUTE, 400, "A,B,@,?,-,%,\"")

]
)
def test_list_jobs(machine, expected_response_code, jobs, headers):
	url = "{}".format(JOBS_URL)
	headers.update({"X-Machine-Name": machine})
	params = {"jobs": jobs}
	resp = requests.get(url, headers=headers, params=params)
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test Retrieve job information
@pytest.mark.parametrize("machine, expected_response_code, jobid",
[

# 1 - valid compute server
(SERVER_COMPUTE, 200, 100), 

# 2 - unknown compute server
("someservernotavailable", 400, 101),

# 3 - compute server not specified
("", 400, 102)

])
def test_list_job(machine, expected_response_code, jobid, headers):
	url = "{}/{}".format(JOBS_URL, jobid)
	headers.update({"X-Machine-Name": machine})
	resp = requests.get(url, headers=headers)
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test cancel job from slurm
@pytest.mark.parametrize("machine, expected_response_code, jobid",
[

# 1 - valid compute server
(SERVER_COMPUTE, 200, 100), 

# 2 - unknown compute server
("someservernotavailable", 400, 101),

# 3 - compute server not specified
("", 400, 102)

])
def test_cancel_job(machine, expected_response_code, jobid, headers):
	url = "{}/{}".format(JOBS_URL, jobid)
	headers.update({"X-Machine-Name": machine})
	resp = requests.delete(url, headers=headers)
	print(resp.content)
	assert resp.status_code == expected_response_code


# Test get account information with sacct command
@pytest.mark.parametrize("machine, expected_response_code, jobid",
[

# 1 - valid compute server
(SERVER_COMPUTE, 200, 100), 

# 2 - unknown compute server
("someservernotavailable", 400, 101),

# 3 - compute server not specified
("", 400, 102),

# 4 - acct with multiple job ids
(SERVER_COMPUTE, 200, "100,200")

#TODO: should we test jobs, starttime, and endtime params validation?

])
def test_acct(machine, expected_response_code, jobid, headers):
	url = "{}/acct".format(COMPUTE_URL)
	headers.update({"X-Machine-Name": machine})
	params = {"jobs":jobid}
	resp = requests.get(url, headers=headers, params=params)
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

