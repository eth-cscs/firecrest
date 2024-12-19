#
#  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import pytest
import platform
import requests
import os
import time
from test_globals import *
import urllib.request, urllib.parse, urllib.error
from markers import skipif_not_uses_gateway

### SSL parameters
SSL_ENABLED = (os.environ.get("F7T_SSL_ENABLED","false").lower() == "true")
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_PATH = "../../../deploy/test-build"

FIRECREST_URL = os.environ.get("FIRECREST_URL")
if FIRECREST_URL:
    TASKS_URL = os.environ.get("FIRECREST_URL") + "/tasks"
    STORAGE_URL = os.environ.get("FIRECREST_URL") + "/storage"
    UTILITIES_URL = os.environ.get("FIRECREST_URL") + "/utilities"
else:
    F7T_SCHEME_PROTOCOL = ("https" if SSL_ENABLED else "http")
    
    TASKS_HOST = os.environ.get("F7T_TASKS_HOST","127.0.0.1") 
    TASKS_PORT = os.environ.get("F7T_TASKS_PORT","5003")
    TASKS_URL = f"{F7T_SCHEME_PROTOCOL}://{TASKS_HOST}:{TASKS_PORT}"

    STORAGE_HOST = os.environ.get("F7T_STORAGE_HOST","127.0.0.1") 
    STORAGE_PORT = os.environ.get("F7T_STORAGE_PORT","5002")
    STORAGE_URL = f"{F7T_SCHEME_PROTOCOL}://{STORAGE_HOST}:{STORAGE_PORT}"

    UTILITIES_HOST = os.environ.get("F7T_UTILITIES_HOST","127.0.0.1") 
    UTILITIES_PORT = os.environ.get("F7T_UTILITIES_PORT","5004")
    UTILITIES_URL = f"{F7T_SCHEME_PROTOCOL}://{UTILITIES_HOST}:{UTILITIES_PORT}"

# same server used for utilities and external upload storage
SERVER_UTILITIES_STORAGE = os.environ.get("F7T_SYSTEMS_PUBLIC_NAME").strip('\'"').split(";")[0]
OBJECT_STORAGE = os.environ.get("F7T_OBJECT_STORAGE", "s3v4")


def get_task(task_id, headers):
    headers["X-Machine-Name"] = SERVER_UTILITIES_STORAGE
    url = f"{TASKS_URL}/{task_id}"
    resp = requests.get(url, headers=headers, verify=False)
    print(resp.content)
    assert resp.status_code == 200
    return resp

def check_task_status(task_id, headers, final_expected_status = 200): # could be 200, 300, 301, 400
    time.sleep(2) # make sure task is created??
    headers["X-Machine-Name"] = SERVER_UTILITIES_STORAGE
    resp = get_task(task_id, headers)
    status = int(resp.json()["task"]["status"])
    assert status == 100 or status == 101 or status == final_expected_status


# test external file upload
@skipif_not_uses_gateway
@pytest.mark.parametrize("targetPath,  expected_response_code", 
                         [ (USER_HOME, 201) ,                            
                           (f"{USER_HOME}/copied_file", 201), 
                           (f"{USER_HOME}/fake_dir/copied_file", 400), 
                           ("/copied_file", 400) ,         
                           
                        ])
def test_post_upload_request(headers,targetPath, expected_response_code):

    headers["X-Machine-Name"] = SERVER_UTILITIES_STORAGE
    # request upload form
    data = { "sourcePath": "testsbatch.sh", "targetPath": targetPath  }
    resp = requests.post(STORAGE_URL + "/xfer-external/upload", headers=headers, data=data, verify=False)
    assert resp.status_code == expected_response_code 

    if expected_response_code != 201:
        return True

    task_id = resp.json()["task_id"]

    # wait to make sure upload form is ready
    time.sleep(5)

    # get upload form from checking task status
    resp = get_task(task_id, headers)
    assert int(resp.json()["task"]["status"]) == 111 # if form upload ready

    # upload file to storage server
    msg = resp.json()["task"]["data"]["msg"]
    url = msg["parameters"]["url"] # "http://svc-minio:9000/service-account-firecrest-sample"

    if platform.system() == 'Darwin':
        ix = url.index("//")
        jx = url.index(":",ix)
        url=url.replace(url[ix+2:jx],"127.0.0.1")

    resp = None

    if (OBJECT_STORAGE == "s3v2"):
        params = [('AWSAccessKeyId', msg["parameters"]["params"]["AWSAccessKeyId"]), ('Signature', msg["parameters"]["params"]["Signature"]), ('Expires', msg["parameters"]["params"]["Expires"])]

        # this way doesn't work
        # files = {'file': ("testsbatch.sh", open(data["sourcePath"], 'rb'))}
        # resp = requests.put(url=url, files=files, params)

        # this is the only way signature doesn't break!
        with open(data["sourcePath"], 'rb') as data:
            resp= requests.put(url, data=data, params=params, verify=False)

    elif (OBJECT_STORAGE == "s3v4"):
        post_data =  [('key', msg["parameters"]["data"]["key"]), ('policy', msg["parameters"]["data"]["policy"]), ('x-amz-algorithm', msg["parameters"]["data"]["x-amz-algorithm"])
        , ('x-amz-credential', msg["parameters"]["data"]["x-amz-credential"]), ('x-amz-date', msg["parameters"]["data"]["x-amz-date"]),
        ('x-amz-signature', msg["parameters"]["data"]["x-amz-signature"])]

        files = {'file': open(data["sourcePath"],'rb')}
        resp = requests.post(url, data=post_data, files=files, verify=False)

    else:
        # swift post request
        params = [('max_file_size', msg["max_file_size"]), ('max_file_count', msg["max_file_count"]), ('expires', msg["expires"]),
        ('signature', msg["signature"]), ('redirect', msg["redirect"])]

        with open(data["sourcePath"], 'rb') as data:
            resp= requests.put(url, data=data, params=params, verify=False)

    print(resp.text)

    assert resp.status_code == 200 or resp.status_code == 204 #TODO: check 204 is right

    # download from OS to FS is automatic
    download_ok = False
    for i in range(20):
        r = get_task(task_id, headers)
        if r.json()["task"]["status"] == "114": # import async_tasks -> async_tasks.ST_DWN_END
            download_ok = True
            break
        if r.json()["task"]["status"] == "115": # async_task.ST_DWN_ERR
            break
        time.sleep(10)
    print(r)
    assert download_ok


## Test external download /storage/xfer-external/download and invalidate URL after download
@skipif_not_uses_gateway
def test_post_download_request(headers):
    headers["X-Machine-Name"] = SERVER_UTILITIES_STORAGE
    # request upload form
    data = { "sourcePath": "/ssh_command_wrapper.sh" }
    resp = requests.post(f"{STORAGE_URL}/xfer-external/download", headers=headers, data=data, verify=False)
    assert resp.status_code == 201

    task_id = resp.json()["task_id"]

    # wait to make sure upload form is ready
    time.sleep(5)

    # get upload form from checking task status
    resp = get_task(task_id, headers)


    assert not (int(resp.json()["task"]["status"])) == 118 # if not error, continue

    upload_ok = False
    for i in range(20):
        resp = get_task(task_id, headers)
        if int(resp.json()["task"]["status"]) == 116: # if file still not in Object Storage, continue
            continue
        if int(resp.json()["task"]["status"]) == 117: # file ready in Object Storage, finish
            upload_ok = True
            break
        time.sleep(10)

    assert upload_ok
    # invalidate:

    headers["X-Task-Id"] = task_id
    resp = requests.post(f"{STORAGE_URL}/xfer-external/invalidate", headers=headers, verify=False)

    assert resp.status_code == 201

# Test storage internal copy and then use utilities list command
# to check copied file
@skipif_not_uses_gateway
@pytest.mark.parametrize("machine", [SERVER_UTILITIES_STORAGE])
def test_internal_cp(machine, headers):
    headers["X-Machine-Name"] = SERVER_UTILITIES_STORAGE
    data = {"sourcePath": USER_HOME + "/testsbatch.sh", "targetPath": USER_HOME + "/testsbatch2.sh"}
    url = f"{STORAGE_URL}/xfer-internal/cp"
    resp = requests.post(url, headers=headers,data=data, verify=False)
    assert resp.status_code == 201

    task_id = resp.json()["task_id"]
    check_task_status(task_id, headers)

     # wait to make sure job is finished
    time.sleep(5)

    # ls /home/testuser/testsbatch2.sh
    params = {"targetPath": USER_HOME + "/testsbatch.sh", "showhidden" : "true"}
    url = f"{UTILITIES_URL}/ls"
    headers.update({"X-Machine-Name": machine})
    resp = requests.get(url, headers=headers, params=params, verify=False)
    print(resp.json())
    print(machine)
    assert resp.status_code == 200


if __name__ == '__main__':
	pytest.main()


