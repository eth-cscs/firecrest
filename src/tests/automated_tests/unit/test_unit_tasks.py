import pytest
import requests
import json
import os
from markers import host_environment_test

FIRECREST_URL = os.environ.get("FIRECREST_URL")
if FIRECREST_URL:
	TASKS_URL = os.environ.get("FIRECREST_URL") + "/tasks"
else:
    TASKS_URL = os.environ.get("F7T_TASKS_URL")

### SSL parameters
USE_SSL = os.environ.get("F7T_USE_SSL", False)
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_PATH = "../../../deploy/test-build"

INVALID_CODE1 = "9999"
INVALID_CODE2 = "47777"

# common status codes
QUEUED   = "100"
PROGRESS = "101"
SUCCESS  = "200"
DELETED  = "300"
EXPIRED  = "301"
ERROR    = "400"

# upload process states
ST_URL_ASK = "110" # ask for Temp Form URL for upload xternal file to Object Storage
ST_URL_REC = "111" # received Temp Form URL for upload xternal file to Object Storage
ST_UPL_CFM = "112" # on upload process: upload to Object Storage confirmed
ST_DWN_BEG = "113" # on upload process: download from Object Storage to cluster started
ST_DWN_END = "114" # on upload process: download from Object Storage to cluster finished
ST_DWN_ERR = "115" # on upload process: download from Object Storage to cluster error

# download process states:
ST_UPL_BEG = "116" # on download process: start upload from filesystem to Object Storage
ST_UPL_END = "117" # on download process: upload from filesystem to Object Storage is finished
ST_UPL_ERR = "118" # on download process: upload from filesystem to Object Storage is erroneous




# for testing update task status
STATUS_CODES = [(QUEUED, "queued", 200), (PROGRESS, "progress", 200), (SUCCESS, "success", 200), (DELETED, "deleted", 200), (EXPIRED, "expired", 200), (ERROR, "error", 200), (ST_URL_ASK, "st_url_ask", 200), (ST_URL_REC, "st_url_rec", 200), (ST_UPL_CFM, "st_upl_cfm", 200), (ST_DWN_BEG, "st_dwn_beg", 200), (ST_DWN_END, "st_dwn_end", 200), (ST_DWN_ERR, "std_dwn_err", 200), (ST_UPL_BEG, "st_upl_beg", 200), (ST_UPL_END, "st_upl_end", 200), (ST_UPL_ERR, "stl_up_err", 200), 
(INVALID_CODE1, "invalid_code1", 400), (INVALID_CODE2, "invalid_code2", 400), 
(QUEUED, None, 200), (INVALID_CODE2, None, 400)]



# helper function to create a task
def create_task(headers):
	url = "{}".format(TASKS_URL)
	resp = requests.post(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False) )
	print(resp.content)
	print(url)
	return resp


# Test list all tasks
def test_list_tasks(headers):
	url = "{}/".format(TASKS_URL)
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(json.dumps(resp.json(),indent=2))
	print(url)
	assert resp.status_code == 200
	

# Test task creation
@host_environment_test
def test_create_task(headers):
	resp = create_task(headers)
	assert resp.status_code == 201
	

# Test query task status
@host_environment_test
def test_get_task(headers):
	resp = create_task(headers)
	hash_id = resp.json()["hash_id"]	
	url = "{}/{}".format(TASKS_URL, hash_id)
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(json.dumps(resp.json(),indent=2))
	assert resp.status_code == 200


# Test query tasks which doesn't exists
def test_get_task_not_exists(headers):
	hash_id = "IDONTEXIST"
	url = "{}/{}".format(TASKS_URL, hash_id)
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	assert resp.status_code == 404


# Test update status by form data
@host_environment_test
@pytest.mark.parametrize("status, msg, expected_response_code", STATUS_CODES)
def test_update_task_formdata(headers, status, msg, expected_response_code):
	resp = create_task(headers)
	hash_id = resp.json()["hash_id"]
	assert resp.status_code == 201

	url = "{}/{}".format(TASKS_URL, hash_id)

	#FORM data	
	resp = requests.put(url, headers=headers, data={'status': status, 'msg': msg}, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	assert resp.status_code == expected_response_code 


# Test update status by json data
@host_environment_test
@pytest.mark.parametrize("status, msg, expected_response_code", STATUS_CODES)
def test_update_task_jsondata(headers, status, msg, expected_response_code):
	resp = create_task(headers)
	hash_id = resp.json()["hash_id"]
	assert resp.status_code == 201

	url = "{}/{}".format(TASKS_URL, hash_id)

	#JSON data
	json={"status": status, "msg": msg}
	resp = requests.put(url, headers=headers, json=json, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	assert resp.status_code == expected_response_code


# Test delete task that exists
@host_environment_test
def test_delete_task_id_exists(headers):
	resp = create_task(headers)
	hash_id = resp.json()["hash_id"]
	url = "{}/{}".format(TASKS_URL, hash_id)
	resp = requests.delete(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	assert resp.status_code == 204


# Test delete task that doesn't exists
@host_environment_test
def test_delete_task_id_not_exists(headers):
	hash_id = "IDONTEXIST"
	url = "{}/{}".format(TASKS_URL, hash_id)
	resp = requests.delete(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	assert resp.status_code == 404 and "error" in resp.json()


# Test expire task 
@host_environment_test
def test_expire_task(headers):
	resp = create_task(headers)
	hash_id = resp.json()["hash_id"]
	url = "{}/expire/{}".format(TASKS_URL, hash_id)
	resp = requests.post(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	assert resp.status_code == 200 and "success" in resp.json()


# Test expire task that doesn't exists
@host_environment_test
def test_expire_task_id_not_exists(headers):
	hash_id = "IDONTEXIST"
	url = "{}/expire/{}".format(TASKS_URL, hash_id)
	resp = requests.post(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	assert resp.status_code == 404 and "error" in resp.json()


@host_environment_test
def test_status():
	url = "{}/status".format(TASKS_URL)
	resp = requests.get(url, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	assert resp.status_code == 200


@host_environment_test
def test_taskslist():
	url = "{}/taskslist".format(TASKS_URL)
	json = {"service": "storage", "status_code":[]}
	resp = requests.get(url, json=json, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	assert resp.status_code == 200


if __name__ == '__main__':
	pytest.main()
