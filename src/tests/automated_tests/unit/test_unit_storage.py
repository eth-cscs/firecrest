import pytest
import requests
import os
from markers import host_environment_test

FIRECREST_IP = os.environ.get("FIRECREST_IP")
if FIRECREST_IP:
	STORAGE_URL = os.environ.get("FIRECREST_IP") + "/storage"
else:
    STORAGE_URL = os.environ.get("STORAGE_URL")



# test upload request: ask for an upload task (must throw 200 OK)
def test_post_upload_request(headers):
    data = { "sourcePath": "testsbatch.sh", "targetPath": "/home/testuser" }
    resp = requests.post(STORAGE_URL + "/xfer-external/upload", headers=headers, data=data)
    assert resp.status_code == 200


# Test an invalid upload task
def test_put_upload_request(headers):
    task_id = "-1"
    headers.update({"X-Task-ID": task_id})
    r = requests.put(STORAGE_URL + "/xfer-external/upload", headers=headers)
    assert r.status_code == 404


def test_download(headers):
    data = { "sourcePath": "testsbatch.sh" }
    resp = requests.post(STORAGE_URL + "/xfer-external/download", headers=headers, data=data)
    assert resp.status_code == 200


def test_internal_cp(headers):
    # jobName, time, stageOutJobId
    data = {"sourcePath":"/home/testuser/testsbatch.sh", "targetPath":"/home/testuser/testsbatch2.sh"}
    url = "{}/xfer-internal/cp".format(STORAGE_URL)
    resp = requests.post(url, headers=headers,data=data)
    assert resp.status_code == 201


def test_internal_mv(headers):
    # jobName, time, stageOutJobId
    data = {"sourcePath":"/home/testuser/testsbatch2.sh", "targetPath":"/home/testuser/testsbatch3.sh"}
    url = "{}/xfer-internal/mv".format(STORAGE_URL)
    resp = requests.post(url, headers=headers,data=data)
    assert resp.status_code == 201


def test_internal_rsync(headers):
    # jobName, time, stageOutJobId
    data = {"sourcePath":"/home/testuser/", "targetPath":"/home/testuser/"}
    url = "{}/xfer-internal/rsync".format(STORAGE_URL)
    resp = requests.post(url, headers=headers,data=data)
    assert resp.status_code == 201   


def test_internal_rm(headers):
    # jobName, time, stageOutJobId
    data = {"targetPath":"/home/testuser/testsbatch3.sh"}
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
