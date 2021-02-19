#
#  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import pytest
import requests
import os
import json
import datetime
import time
from conftest import headers  # header fixture

pytestmark = pytest.mark.reservations

# Requests Parameters
FIRECREST_URL = os.environ.get("FIRECREST_URL")
if FIRECREST_URL:
	RESERVATIONS_URL = os.environ.get("FIRECREST_URL") + "/reservations"
else:
    RESERVATIONS_URL = os.environ.get("F7T_RESERVATIONS_URL")
SYSTEM = os.environ.get("F7T_SYSTEMS_PUBLIC").split(";")[0]

# SSL parameters
USE_SSL = os.environ.get("F7T_USE_SSL", False)
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_PATH = "../../../deploy/test-build"
verify = (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False)

# Time examples
d1 = (datetime.datetime.now() + datetime.timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%S")
d2 = (datetime.datetime.now() + datetime.timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%S") # 1 hour difference

d3 = (datetime.datetime.now() + datetime.timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M") # wrong format
d4 = (datetime.datetime.now() + datetime.timedelta(hours=13)).strftime("%Y-%m-%dT%H:%M") # wrong format

d5 = (datetime.datetime.now() + datetime.timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%S")
d6 = (datetime.datetime.now() + datetime.timedelta(hours=13)).strftime("%Y-%m-%dT%H:%M:%S")

d7 = (datetime.datetime.now() + datetime.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
d8 = (datetime.datetime.now() + datetime.timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%S")


def check_status(response, expected_code):
	assert response.status_code == expected_code, "headers: {}, content: {}".format(response.headers, response.content)


@pytest.mark.parametrize("system,expected_code,expected_data",[
						(SYSTEM, 200, []),
						("notavalidsystem", 400, 'Error listing reservation')])
def test_list_reservation(system, expected_code, expected_data, headers):
	url = RESERVATIONS_URL
	headers["X-Machine-Name"] = system

	resp = requests.get(url, headers=headers, verify=verify)
	check_status(resp, expected_code)

	# NOTE: The api needs to harmonize the response schema here :/
	if expected_code == 200:
		assert resp.json()['success'] == expected_data
	else:
		assert resp.json()['error'] == expected_data


POST_DATA = [(201, "testrsvok01", "test",  "1", "f7t", d1, d2),
		     (201, "testrsvok02", "test",  "1", "f7t", d5, d6),
             (400, "testrsvok01", "test",  "1", "f7t", d1, d2), # fail, duplicated reservation name
			 (400, "testrsverr02", "test", "1", "f7t", d2, d1), # fail: dates are in wrong order
             (400, "testrsverr03", "test", "1", "ntl", d2, d1), # fail: invalid nodeType
			 (400, "testrsverr04", "test", "1", "f7t", d3, d4), # fail: wrong date time format
			 (400, "",            "test",  "1", "f7t", d5, d6), # fail: no reservation name
			 (400, "testrsverr05", None,   "1", "f7t", d5, d6), # fail: no account given
			 (400, "testrsverr06", "test", "3", "f7t", d5, d6), # fail: required more nodes than available
			 (400, "testrsverr07", "test", "1", None,  d5, d6), # fail: no nodeType given
			 (400, "testrsverr08", None,   "1", "f7t", None,d6), # fail: no starttime given
			 (400, "testrsverr09", None,   "1", "f7t", d5, None), # fail: no endtime given
]
@pytest.mark.parametrize("status_code,reservation,account,numberOfNodes,nodeType,starttime,endtime",POST_DATA)
def test_post_reservation(status_code,reservation,account,numberOfNodes,nodeType,starttime,endtime,headers):
	url = RESERVATIONS_URL
	headers["X-Machine-Name"] = SYSTEM
	data = {"reservation":   reservation,
			"account":       account,
			"numberOfNodes": numberOfNodes,
			"nodeType":      nodeType,
			"starttime":     starttime,
			"endtime":       endtime}

	resp = requests.post(url, headers=headers, data=data, verify=verify)
	check_status(resp, status_code)


PUT_DATA = [(400, "testrsvok01", "1", "f7t", d5, d6), # fail overlap with testrsvok01
			(200, "testrsvok01", "1", "f7t", d7, d8), # ok
            (400, "testrsvok01", "1", "f7t", d2, d1), # fail: dates are in wrong order
            (400, "testrsvok01", "1", "ntl", d5, d6), # fail: invalid nodeType
			(400, "testrsvok01", "1", "f7t", d3, d4), # fail: wrong date time format
			(405, "",            "1", "f7t", d5, d6), # fail: no reservation name, method not allowed
			(400, "wrongname",   "1", "f7t", d5, d6), # fail: wrong reservation name
			(400, "testrsvok01", "3", "f7t", d5, d6), # fail: required more nodes than available
			(400, "testrsvok01", "1", None,  d5, d6), # fail: no nodeType given
			(400, "testrsvok01", "1", "f7t", None, d6), # fail: no starttime given
			(400, "testrsvok01", "1", "f7t", d5, None), # fail: no endtime given
]
@pytest.mark.parametrize("status_code,reservation,numberOfNodes,nodeType,starttime,endtime", PUT_DATA)
def test_put_reservation(status_code, reservation, numberOfNodes, nodeType, starttime, endtime, headers):
	url = f"{RESERVATIONS_URL}/{reservation}"
	headers["X-Machine-Name"] = SYSTEM
	data = {"numberOfNodes": numberOfNodes,
			"nodeType":      nodeType,
			"starttime":     starttime,
			"endtime":       endtime}

	resp = requests.put(url, headers=headers, data=data , verify=verify)
	check_status(resp, status_code)


DELETE_DATA =  [(204, "testrsvok01"), # OK
				(204, "testrsvok02"), # OK
				(400, "wrongname"),   # fail: wrong name
]
@pytest.mark.parametrize("status_code,reservation",DELETE_DATA)
def test_delete_reservation(status_code, reservation, headers):
	url = f"{RESERVATIONS_URL}/{reservation}"
	headers["X-Machine-Name"] = SYSTEM

	resp = requests.delete(url, headers=headers, verify=verify)
	check_status(resp, status_code)


if __name__ == '__main__':
	pytest.main()