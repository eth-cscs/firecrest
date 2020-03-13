import pytest
import requests
import os
import time

import urllib.request, urllib.parse, urllib.error

FIRECREST_IP = os.environ.get("FIRECREST_IP")
if FIRECREST_IP:
    TASKS_URL = os.environ.get("FIRECREST_IP") + "/tasks"
    STORAGE_URL = os.environ.get("FIRECREST_IP") + "/storage"
    UTILITIES_URL = os.environ.get("FIRECREST_IP") + "/utilities"
else:
    TASKS_URL = os.environ.get("TASKS_URL")
    STORAGE_URL = os.environ.get("STORAGE_URL")
    UTILITIES_URL = os.environ.get("UTILITIES_URL")

# same server used for utilities and external upload storage
SERVER_UTILITIES_STORAGE = os.environ.get("SYSTEMS_PUBLIC").split(";")[0] 
OBJECT_STORAGE = os.environ.get("OBJECT_STORAGE")

def get_task(task_id, headers):
	url = "{}/{}".format(TASKS_URL, task_id)
	resp = requests.get(url, headers=headers)
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
    data = { "sourcePath": "testsbatch.sh", "targetPath": "/home/testuser" }
    resp = requests.post(STORAGE_URL + "/xfer-external/upload", headers=headers, data=data)
    print(resp.content)
    assert resp.status_code == 200

    task_id = resp.json()["task_id"]

    # wait to make sure upload form is ready
    time.sleep(2)

    # get upload form from checking task status
    resp = get_task(task_id, headers)
    print(resp.content)
    assert int(resp.json()["task"]["status"]) == 111 # if form upload ready

    # upload file to storage server
    msg = resp.json()["task"]["data"]["msg"]
    url = msg["url"]

    resp = None
    
    if (OBJECT_STORAGE == "s3v2"):
        params = [('AWSAccessKeyId', msg["AWSAccessKeyId"]), ('Signature', msg["Signature"]), ('Expires', msg["Expires"])]
        
        # this way doesn't work
        # files = {'file': ("testsbatch.sh", open(data["sourcePath"], 'rb'))}
        # resp = requests.put(url=url, files=files, params)
        
        # this is the only way signature doesn't break!
        with open(data["sourcePath"], 'rb') as data:
            resp= requests.put(url, data=data, params=params)

    elif (OBJECT_STORAGE == "s3v4"):
        post_data =  [('key', msg["key"]), ('policy', msg["policy"]), ('x-amz-algorithm', msg["x-amz-algorithm"])
        , ('x-amz-credential', msg["x-amz-credential"]), ('x-amz-date', msg["x-amz-date"]),
        ('x-amz-signature', msg["x-amz-signature"])]

        files = {'file': open(data["sourcePath"],'rb')}
        resp = requests.post(url, data=post_data, files=files)

    else:
        # swift post request
        params = [('max_file_size', msg["max_file_size"]), ('max_file_count', msg["max_file_count"]), ('expires', msg["expires"]),
        ('signature', msg["signature"]), ('redirect', msg["redirect"])]
        
        with open(data["sourcePath"], 'rb') as data:
            resp= requests.put(url, data=data, params=params)
            
    print(resp.content)
    assert resp.status_code == 200 or resp.status_code == 204 #TODO: check 204 is right

    # inform upload finished
    headers.update({"X-Task-ID": task_id})
    r = requests.put(STORAGE_URL + "/xfer-external/upload", headers=headers)
    print(r.content)
    
    assert r.status_code == 200





# Test storage internal copy and then use utilities list command
# to check copied file
@pytest.mark.parametrize("machine", [SERVER_UTILITIES_STORAGE])
def test_internal_cp(machine, headers):
    # jobName, time, stageOutJobId
    data = {"sourcePath":"/home/testuser/testsbatch.sh", "targetPath":"/home/testuser/testsbatch2.sh"}
    url = "{}/xfer-internal/cp".format(STORAGE_URL)
    resp = requests.post(url, headers=headers,data=data)
    assert resp.status_code == 201

    task_id = resp.json()["task_id"]
    check_task_status(task_id, headers)
    
     # wait to make sure job is finished
    time.sleep(5)

    # ls /home/testuser/testsbatch2.sh
    params = {"targetPath": "/home/testuser/testsbatch.sh", "showhidden" : "true"}
    url = "{}/ls".format(UTILITIES_URL)
    headers.update({"X-Machine-Name": machine})
    resp = requests.get(url, headers=headers, params=params)
    print(resp.json())
    print(machine)
    assert resp.status_code == 200


if __name__ == '__main__':
	pytest.main()


