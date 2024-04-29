#
#  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import pytest
import requests
import os
import datetime
from markers import skipif_not_uses_gateway

pytestmark = pytest.mark.reservations

# SSL parameters
SSL_ENABLED = (os.environ.get("F7T_SSL_ENABLED","false").lower() == "true")
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_PATH = "../../../deploy/test-build"

# Requests Parameters
FIRECREST_URL = os.environ.get("FIRECREST_URL")
USE_GATEWAY  = (os.environ.get("USE_GATEWAY","false").lower() == "true")

if FIRECREST_URL and USE_GATEWAY:
	RESERVATIONS_URL = os.environ.get("FIRECREST_URL") + "/reservations"
else:
	F7T_SCHEME_PROTOCOL = ("https" if SSL_ENABLED else "http")
	RESERVATIONS_HOST = os.environ.get("F7T_RESERVATIONS_HOST","127.0.0.1") 
	RESERVATIONS_PORT = os.environ.get("F7T_RESERVATIONS_PORT","5005")
	RESERVATIONS_URL = f"{F7T_SCHEME_PROTOCOL}://{RESERVATIONS_HOST}:{RESERVATIONS_PORT}"

SYSTEM = os.environ.get("F7T_SYSTEMS_PUBLIC_NAME").strip('\'"').split(";")[0]

print(f"RESERVATIONS_URL: {RESERVATIONS_URL}")

# Time examples
d1 = (datetime.datetime.now() + datetime.timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%S")
d2 = (datetime.datetime.now() + datetime.timedelta(days=6)).strftime("%Y-%m-%dT%H:%M:%S")
d3 = (datetime.datetime.now() + datetime.timedelta(days=12)).strftime("%Y-%m-%dT%H:%M") # wrong format
d4 = (datetime.datetime.now() + datetime.timedelta(days=13)).strftime("%Y-%m-%dT%H:%M") # wrong format
d5 = (datetime.datetime.now() + datetime.timedelta(days=12)).strftime("%Y-%m-%dT%H:%M:%S")
d6 = (datetime.datetime.now() + datetime.timedelta(days=13)).strftime("%Y-%m-%dT%H:%M:%S")

@skipif_not_uses_gateway
def test_list_reservations_empty(headers):
	url = RESERVATIONS_URL
	headers["X-Machine-Name"] = SYSTEM
	check_no_reservations(url, headers)

@skipif_not_uses_gateway
def test_list_reservations_wrong(headers):
	url = RESERVATIONS_URL
	headers["X-Machine-Name"] = "notavalidsystem"

	resp = requests.get(url, headers=headers, verify=False)
	check_response(resp, 400)
	assert resp.json()['error'] == 'Error listing reservation'


# You can find the valid options for accounts, node types, etc in the slurm config files of the cluster built for these tests.
POST_DATA = [
	(400, None,           "test", "1", "f7t", d1, d2, "\'reservation\' form data input missing"),
	(400, "",             "test", "1", "f7t", d1, d2, "\'reservation\' parameter format is not valid"),
	(400, "validrsvname", None,   "1", "f7t", d1, d2, "\'account\' form data input missing"),
	(400, "validrsvname", "",     "1", "f7t", d1, d2, "\'account\' parameter format is not valid"),

	(400, "validrsvname", "test", "3",  "f7t", d1, d2, "greater than 1 available"),
	(400, "validrsvname", "test", "1",  "ntl", d1, d2, "only f7t feature type are supported"),
]
BASE_DATA = [
	(400, "validrsvname", "test", None, "f7t", d1, d2, "\'numberOfNodes\' form data input missing"),
	(400, "validrsvname", "test", "",   "f7t", d1, d2, "\'numberOfNodes\' parameter is not valid"),
	(400, "validrsvname", "test", "-3", "f7t", d1, d2, "\'numberOfNodes\' parameter is not valid"),
	(400, "validrsvname", "test", "0",  "f7t", d1, d2, "\'numberOfNodes\' parameter is not valid"),

	(400, "validrsvname", "test", "1",  None,  d1, d2, "\'nodeType\' form data input missing"),
	(400, "validrsvname", "test", "1",  "",    d1, d2, "\'nodeType\' parameter format is not valid"),

	(400, "validrsvname", "test", "1",  "f7t", None,   d2,   "\'starttime\' form data input missing"),
	(400, "validrsvname", "test", "1",  "f7t", "",     d2,   "\'starttime\' parameter format is not valid"),
	(400, "validrsvname", "test", "1",  "f7t", "2day", d2,   "\'starttime\' parameter format is not valid"),
	(400, "validrsvname", "test", "1",  "f7t", d3,     d4,   "\'starttime\' parameter format is not valid"),
	(400, "validrsvname", "test", "1",  "f7t", d1,     None, "\'endtime\' form data input missing"),
	(400, "validrsvname", "test", "1",  "f7t", d1,     "",   "\'endtime\' parameter format is not valid"),
	(400, "validrsvname", "test", "1",  "f7t", d1,     "2m", "\'endtime\' parameter format is not valid"),
	(400, "validrsvname", "test", "1",  "f7t", d1,     d4,   "\'endtime\' parameter format is not valid"),
	(400, "validrsvname", "test", "1",  "f7t", d2,     d1,   "\'endtime\' occurs before \'starttime\'"),
]
@pytest.mark.parametrize("status_code,reservation,account,numberOfNodes,nodeType,starttime,endtime,msg",POST_DATA + BASE_DATA)
@skipif_not_uses_gateway
def test_post_reservation_wrong(status_code,reservation,account,numberOfNodes,nodeType,starttime,endtime,msg,headers):
	url = RESERVATIONS_URL
	headers["X-Machine-Name"] = SYSTEM
	data = {"reservation":   reservation,
			"account":       account,
			"numberOfNodes": numberOfNodes,
			"nodeType":      nodeType,
			"starttime":     starttime,
			"endtime":       endtime}

	resp = requests.post(url, headers=headers, data=data, verify=False)
	check_response(resp, status_code, msg)

@skipif_not_uses_gateway
@pytest.mark.parametrize("status_code,reservation,account,numberOfNodes,nodeType,starttime,endtime,msg", BASE_DATA)
def test_put_reservation_wrong(status_code,reservation,account,numberOfNodes,nodeType,starttime,endtime,msg,headers):
	url = f"{RESERVATIONS_URL}/{reservation}"
	headers["X-Machine-Name"] = SYSTEM
	data = {"numberOfNodes": numberOfNodes,
			"nodeType":      nodeType,
			"starttime":     starttime,
			"endtime":       endtime}

	resp = requests.put(url, headers=headers, data=data, verify=False)
	check_response(resp, status_code, msg)

@skipif_not_uses_gateway
@pytest.mark.parametrize("status_code,reservation,msg",[
						(400, "wrongname", "You are not an owner of the wrongname reservation"),
						(400, "1_",        "\'reservation\' parameter format is not valid"),
])
def test_delete_reservation_wrong(status_code, reservation, msg, headers):
	url = f"{RESERVATIONS_URL}/{reservation}"
	headers["X-Machine-Name"] = SYSTEM

	resp = requests.delete(url, headers=headers, verify=False)
	check_response(resp, status_code, msg)

@skipif_not_uses_gateway
def test_reservation_crud_conflicts(dummy_resevation, headers):
	url = RESERVATIONS_URL
	headers["X-Machine-Name"] = SYSTEM

	rsv02 = dict(dummy_resevation)
	rsv02['reservation'] = "testrsvok02"

	resp = requests.post(url, headers=headers, data=rsv02, verify=False)
	respd = resp.json().get('description', "")
	if "Requested nodes are busy" in respd:
		# Slurm < 20
		expected_des = "Error creating the reservation: Requested nodes are busy"
	else:
		# Slurm > 20
		expected_des = "Error creating the reservation: Requested node configuration is not available"
	check_response(resp, 400, expected_des)

@skipif_not_uses_gateway
def test_reservation_crud_ok(dummy_resevation, headers):
	url = RESERVATIONS_URL
	headers["X-Machine-Name"] = SYSTEM

	# read reservation
	resp = requests.get(url, headers=headers, verify=False)
	check_response(resp, 200)
	obtained = resp.json().get('success', [])
	assert [x['reservationname'] for x in obtained] == ['testrsvok01']

	# update rsv1
	upd = {
		"numberOfNodes": "1",
		"nodeType":      "f7t",
		"starttime": d5,
		"endtime": d6
	}
	resp = requests.put(f"{RESERVATIONS_URL}/testrsvok01", headers=headers, data=upd, verify=False)
	check_response(resp, 200)

@pytest.fixture
def dummy_resevation(headers):
	url = RESERVATIONS_URL
	headers["X-Machine-Name"] = SYSTEM

	rsv01 = {
		"reservation":   "testrsvok01",
		"account":       "test",
		"numberOfNodes": "1",
		"nodeType":      "f7t",
		"starttime":     d1,
		"endtime":       d2,
	}

	check_no_reservations(url, headers)

	# create rsv1
	resp = requests.post(url, headers=headers, data=rsv01, verify=False)
	check_response(resp, 201)

	yield rsv01

	# delete rsv1
	resp = requests.delete(f"{RESERVATIONS_URL}/testrsvok01", headers=headers, verify=False)
	check_response(resp, 204)
	check_no_reservations(url, headers)


def check_response(response, expected_code, in_description=None):
	assert response.status_code == expected_code, "headers: {}, content: {}".format(response.headers, response.content)
	if in_description:
		assert in_description in response.json().get('description', "")


def check_no_reservations(url, headers):
	resp = requests.get(url, headers=headers, verify=False)
	check_response(resp, 200)
	obtained = resp.json()['success']
	assert obtained == []


if __name__ == '__main__':
	pytest.main()