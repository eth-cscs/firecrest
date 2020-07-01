import pytest
import requests
import os
from markers import host_environment_test
from test_globals import *
from pytest_cases import parametrize_plus, fixture_plus, fixture_ref

FIRECREST_URL = os.environ.get("FIRECREST_URL")
if FIRECREST_URL:
	STORAGE_URL = os.environ.get("FIRECREST_URL") + "/storage"
else:
    STORAGE_URL = os.environ.get("F7T_STORAGE_URL")




# test upload request: api method validates targetPath ... but not sourcePath??
@parametrize_plus("sourcePath, targetPath, expected_response_code, headers", 
[ 

# 1 - valid sourcePath and targetPath 
("testsbatch.sh", USER_HOME, 200, fixture_ref(headers)),

# 2 - invalid sourcePath
("notexists", USER_HOME, 400, fixture_ref(headers)),

# 3 - invalid targetPath
("testsbatch.sh", "notexists", 400, fixture_ref(headers)),

# 4 - sourcePath empty
("", USER_HOME, 400, fixture_ref(headers)),

# 5 - targetpath empty
("testsbatch.sh", "", 400, fixture_ref(headers)),

])
def test_post_upload_request(sourcePath, targetPath, expected_response_code, headers):
    data = { "sourcePath": sourcePath, "targetPath": targetPath}
    resp = requests.post(STORAGE_URL + "/xfer-external/upload", headers=headers, data=data)
    assert resp.status_code == expected_response_code



# test download invalid files. Valid file download should be done in integration test 
# (since it requires a previous succesful file upload)
@pytest.mark.parametrize("sourcePath, expected_response_code", 
[ 

# 1 - file not exists
("no-existing-file", 400) , 

# 2 - forbbiden file
("/etc/hosts", 400),

# 3 - file not specified
("", 400)

])
def test_download_file(sourcePath, expected_response_code, headers):
    data = { "sourcePath": sourcePath }
    resp = requests.post(STORAGE_URL + "/xfer-external/download", headers=headers, data=data) 
    print(resp.json())  
    print(resp.headers)
    assert resp.status_code == expected_response_code



# Tests invalid internal copy requests. Valid internal cp test should be done in integration test 
# (since it requires a previous succesful file upload)
@pytest.mark.parametrize("sourcePath, targetPath, time, expected_response_code", [

# 1 - file.txt doesn't exists, but it should work since the method doesn't validate sourcePath
("file.txt",  "file2.txt", None, 201),

# 2 - empty sourcePath
("",  "file2.txt", None, 400),

# 3 - empty targetPath
("file.txt",  "", None, 400),

# 4 - valid date format (default is 2:00:00 H:M:s)
("file.txt",  "file2.txt", "2:00:00 05:00:30", 201),

# 5 - invalid date format,   
("file.txt",  "file2.txt", "25:00:00 07:05:06", 400 )

# 6 - jobName and stageOutJobId params related errors don't return error, so they are not tested ...
])
def test_internal_cp(sourcePath, targetPath, time, expected_response_code, headers):
    data = {"sourcePath": sourcePath, "targetPath": targetPath, "time": time}
    url = "{}/xfer-internal/cp".format(STORAGE_URL)
    resp = requests.post(url, headers=headers,data=data)
    assert resp.status_code == expected_response_code


def test_internal_mv(headers):
    # jobName, time, stageOutJobId
    data = {"sourcePath": USER_HOME + "/testsbatch2.sh", "targetPath": USER_HOME + "/testsbatch3.sh"}
    url = "{}/xfer-internal/mv".format(STORAGE_URL)
    resp = requests.post(url, headers=headers,data=data)
    assert resp.status_code == 201


def test_internal_rsync(headers):
    # jobName, time, stageOutJobId
    data = {"sourcePath": USER_HOME + "/", "targetPath": USER_HOME + "/"}
    url = "{}/xfer-internal/rsync".format(STORAGE_URL)
    resp = requests.post(url, headers=headers,data=data)
    assert resp.status_code == 201   


def test_internal_rm(headers):
    # jobName, time, stageOutJobId
    data = {"targetPath": USER_HOME + "/testsbatch3.sh"}
    url = "{}/xfer-internal/rm".format(STORAGE_URL)
    resp = requests.post(url, headers=headers,data=data)
    assert resp.status_code == 201   


# Test storage microservice status
@host_environment_test
def test_status():
	url = "{}/status".format(STORAGE_URL)
	resp = requests.get(url)
	assert resp.status_code == 200


if __name__ == '__main__':
	pytest.main()
