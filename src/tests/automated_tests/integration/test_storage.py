import pytest
import requests
import os
import time
from test_globals import *
import urllib.request, urllib.parse, urllib.error

FIRECREST_URL = os.environ.get("FIRECREST_URL")
if FIRECREST_URL:
    TASKS_URL = os.environ.get("FIRECREST_URL") + "/tasks"
    STORAGE_URL = os.environ.get("FIRECREST_URL") + "/storage"
    UTILITIES_URL = os.environ.get("FIRECREST_URL") + "/utilities"
else:
    TASKS_URL = os.environ.get("F7T_TASKS_URL")
    STORAGE_URL = os.environ.get("F7T_STORAGE_URL")
    UTILITIES_URL = os.environ.get("F7T_UTILITIES_URL")

# same server used for utilities and external upload storage
SERVER_UTILITIES_STORAGE = os.environ.get("F7T_SYSTEMS_PUBLIC").split(";")[0] 
OBJECT_STORAGE = os.environ.get("F7T_OBJECT_STORAGE")

### SSL parameters
USE_SSL = os.environ.get("F7T_USE_SSL", False)
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_PATH = "../../../deploy/test-build"



def get_task(task_id, headers):
	url = "{}/{}".format(TASKS_URL, task_id)
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == 200
	return resp

def check_task_status(task_id, headers, final_expected_status = 200): # could be 200, 300, 301, 400
	time.sleep(2) # make sure task is created??
	resp = get_task(task_id, headers)
	status = int(resp.json()["task"]["status"])
	assert status == 100 or status == 101 or status == final_expected_status



# test external file upload
def test_post_upload_request(headers):

    # request upload form
    data = { "sourcePath": "testsbatch.sh", "targetPath": USER_HOME }
    resp = requests.post(STORAGE_URL + "/xfer-external/upload", headers=headers, data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
    assert resp.status_code == 201

    task_id = resp.json()["task_id"]

    # wait to make sure upload form is ready
    time.sleep(5)

    # get upload form from checking task status
    resp = get_task(task_id, headers)
    assert int(resp.json()["task"]["status"]) == 111 # if form upload ready

    # upload file to storage server
    msg = resp.json()["task"]["data"]["msg"]
    url = msg["url"]


    url = url.replace("minio_test_build", "127.0.0.1")

    resp = None
    
    if (OBJECT_STORAGE == "s3v2"):
        params = [('AWSAccessKeyId', msg["AWSAccessKeyId"]), ('Signature', msg["Signature"]), ('Expires', msg["Expires"])]
        
        # this way doesn't work
        # files = {'file': ("testsbatch.sh", open(data["sourcePath"], 'rb'))}
        # resp = requests.put(url=url, files=files, params)
        
        # this is the only way signature doesn't break!
        with open(data["sourcePath"], 'rb') as data:
            resp= requests.put(url, data=data, params=params, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))

    elif (OBJECT_STORAGE == "s3v4"):
        post_data =  [('key', msg["key"]), ('policy', msg["policy"]), ('x-amz-algorithm', msg["x-amz-algorithm"])
        , ('x-amz-credential', msg["x-amz-credential"]), ('x-amz-date', msg["x-amz-date"]),
        ('x-amz-signature', msg["x-amz-signature"])]

        files = {'file': open(data["sourcePath"],'rb')}
        resp = requests.post(url, data=post_data, files=files, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))

    else:
        # swift post request
        params = [('max_file_size', msg["max_file_size"]), ('max_file_count', msg["max_file_count"]), ('expires', msg["expires"]),
        ('signature', msg["signature"]), ('redirect', msg["redirect"])]
        
        with open(data["sourcePath"], 'rb') as data:
            resp= requests.put(url, data=data, params=params, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
     
    assert resp.status_code == 200 or resp.status_code == 204 #TODO: check 204 is right

    # download from OS to FS is automatic
    download_ok = False
    for i in range(20):
        r = requests.get(TASKS_URL +"/"+task_id, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
        assert r.status_code == 200
        if r.json()["task"]["status"] == "114": # import async_tasks -> async_tasks.ST_DWN_END
            download_ok = True
            break
        if r.json()["task"]["status"] == "115": # async_task.ST_DWN_ERR
            break
        time.sleep(10)
    print(r)
    assert download_ok



# Test storage internal copy and then use utilities list command
# to check copied file
@pytest.mark.parametrize("machine", [SERVER_UTILITIES_STORAGE])
def test_internal_cp(machine, headers):
    # jobName, time, stageOutJobId
    data = {"sourcePath": USER_HOME + "/testsbatch.sh", "targetPath": USER_HOME + "/testsbatch2.sh"}
    url = "{}/xfer-internal/cp".format(STORAGE_URL)
    resp = requests.post(url, headers=headers,data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
    assert resp.status_code == 201

    task_id = resp.json()["task_id"]
    check_task_status(task_id, headers)
    
     # wait to make sure job is finished
    time.sleep(5)

    # ls /home/testuser/testsbatch2.sh
    params = {"targetPath": USER_HOME + "/testsbatch.sh", "showhidden" : "true"}
    url = "{}/ls".format(UTILITIES_URL)
    headers.update({"X-Machine-Name": machine})
    resp = requests.get(url, headers=headers, params=params, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
    print(resp.json())
    print(machine)
    assert resp.status_code == 200


if __name__ == '__main__':
	pytest.main()


