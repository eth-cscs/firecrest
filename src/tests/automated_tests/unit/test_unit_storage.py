import pytest
import requests
import os
from markers import host_environment_test
from test_globals import *

FIRECREST_URL = os.environ.get("FIRECREST_URL")
if FIRECREST_URL:
	STORAGE_URL = os.environ.get("FIRECREST_URL") + "/storage"
else:
    STORAGE_URL = os.environ.get("STORAGE_URL")


# test upload request: ask for an upload task (must throw 200 OK)
def test_post_upload_request(headers):
    data = { "sourcePath": "testsbatch.sh", "targetPath": USER_HOME }
    resp = requests.post(STORAGE_URL + "/xfer-external/upload", headers=headers, data=data)
    assert resp.status_code == 200


# Test an invalid upload task
def test_put_upload_request(headers):
    task_id = "-1"
    headers.update({"X-Task-ID": task_id})
    r = requests.put(STORAGE_URL + "/xfer-external/upload", headers=headers)
    assert r.status_code == 404


def test_download_file_not_exist(headers):
    data = { "sourcePath": "no-existing-file" }
    resp = requests.post(STORAGE_URL + "/xfer-external/download", headers=headers, data=data) 
    print(resp.json())  
    print(resp.headers)
    assert resp.status_code == 400

def test_download_file_not_allowed(headers):
    data = { "sourcePath": "/etc/hosts" }
    resp = requests.post(STORAGE_URL + "/xfer-external/download", headers=headers, data=data) 
    print(resp.json())  
    print(resp.headers)
    assert resp.status_code == 400


def test_internal_cp(headers):
    # jobName, time, stageOutJobId
    data = {"sourcePath": USER_HOME + "/testsbatch.sh", "targetPath": USER_HOME + "/testsbatch2.sh"}
    url = "{}/xfer-internal/cp".format(STORAGE_URL)
    resp = requests.post(url, headers=headers,data=data)
    assert resp.status_code == 201


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
