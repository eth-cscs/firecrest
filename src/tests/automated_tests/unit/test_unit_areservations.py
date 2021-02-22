#
#  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import pytest
import requests
import os
from test_globals import *
from markers import host_environment_test
import json
import datetime
import time

pytestmark = pytest.mark.reservations

FIRECREST_URL = os.environ.get("FIRECREST_URL")
if FIRECREST_URL:
	RESERVATIONS_URL = os.environ.get("FIRECREST_URL") + "/reservations"
else:
    RESERVATIONS_URL = os.environ.get("F7T_RESERVATIONS_URL")

SYSTEM = os.environ.get("F7T_SYSTEMS_PUBLIC").split(";")[0]

LIST_DATA = [(SYSTEM, 200), ("notavalidsystem", 400)]




d1 = (datetime.datetime.now() + datetime.timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%S")
d2 = (datetime.datetime.now() + datetime.timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%S") # 1 hour difference

d3 = (datetime.datetime.now() + datetime.timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M") # wrong format
d4 = (datetime.datetime.now() + datetime.timedelta(hours=13)).strftime("%Y-%m-%dT%H:%M") # wrong format

d5 = (datetime.datetime.now() + datetime.timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%S") # wrong format
d6 = (datetime.datetime.now() + datetime.timedelta(hours=13)).strftime("%Y-%m-%dT%H:%M:%S") # wrong format

d7 = (datetime.datetime.now() + datetime.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S") # wrong format
d8 = (datetime.datetime.now() + datetime.timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%S") # wrong format

            # parameters:  reservation, account, numberOfNodes, nodeType, starttime, endtime
POST_DATA = [(SYSTEM, 201, "testrsvok01", "test",  "1", 			"f7t",		d1,		d2),
		     (SYSTEM, 201, "testrsvok02", "test",  "1", 			"f7t",		d5,		d6),
             (SYSTEM, 400, "testrsvok01", "test",  "1", 			"f7t",		d1,		d2), # fail, duplicated reservation name
			 (SYSTEM, 400, "testrsverr02", "test", "1", "f7t",d2,d1), # fail: dates are in wrong order
             (SYSTEM, 400, "testrsverr03", "test", "1", "intel",d2,d1), # fail: invalid nodeType
			 (SYSTEM, 400, "testrsverr04", "test", "1", "f7t",d3,d4), # fail: wrong date time format
			 (SYSTEM, 400, "",            "test", "1", "f7t",d5,d6), # fail: no reservation name
			 (SYSTEM, 400, "testrsverr05", None, "1", "f7t",d5,d6), # fail: no account given
			 (SYSTEM, 400, "testrsverr06", "test", "3", "f7t",d5,d6), # fail: required more nodes than available
			 (SYSTEM, 400, "testrsverr07", "test", "1", None,d5,d6), # fail: no nodeType given
			 (SYSTEM, 400, "testrsverr08", None, "1", "f7t",None,d6), # fail: no starttime given
			 (SYSTEM, 400, "testrsverr09", None, "1", "f7t",d5,None), # fail: no endtime given
]

# parameters:                reservation, numberOfNodes, nodeType, starttime, endtime
PUT_DATA =  [(SYSTEM, 400, "testrsvok01", "1", 			"f7t",		d5,		d6), # fail overlap with testrsvok01
			 (SYSTEM, 200, "testrsvok01", "1", 			"f7t",		d7,		d8), # ok
             (SYSTEM, 400, "testrsvok01", "1", "f7t",d2,d1), # fail: dates are in wrong order
             (SYSTEM, 400, "testrsvok01", "1", "intel",d5,d6), # fail: invalid nodeType
			 (SYSTEM, 400, "testrsvok01", "1", "f7t",d3,d4), # fail: wrong date time format
			 (SYSTEM, 405, "",            "1", "f7t",d5,d6), # fail: no reservation name, method not allowed
			 (SYSTEM, 400, "wrongname",   "1", "f7t",d5,d6), # fail: wrong reservation name
			 (SYSTEM, 400, "testrsvok01", "3", "f7t",d5,d6), # fail: required more nodes than available
			 (SYSTEM, 400, "testrsvok01", "1", None,d5,d6), # fail: no nodeType given
			 (SYSTEM, 400, "testrsvok01", "1", "f7t",None,d6), # fail: no starttime given
			 (SYSTEM, 400, "testrsvok01", "1", "f7t",d5,None), # fail: no endtime given

]


# parameters:                reservation, numberOfNodes, nodeType, starttime, endtime
DELETE_DATA =  [(SYSTEM, 204, "testrsvok01"), # OK
			    (SYSTEM, 204, "testrsvok02"), # OK
                (SYSTEM, 400, "wrongname"), # fail: wrong name
]

### SSL parameters
USE_SSL = os.environ.get("F7T_USE_SSL", False)
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_PATH = "../../../deploy/test-build"


@pytest.mark.parametrize("system,status_code",LIST_DATA)
def test_list_reservation(system, status_code, headers):
	url = RESERVATIONS_URL
	headers["X-Machine-Name"] = system
	resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	print(resp.headers)
	assert resp.status_code == status_code


@pytest.mark.parametrize("system,status_code,reservation,account,numberOfNodes,nodeType,starttime,endtime",POST_DATA)
def test_post_reservation(system, status_code,reservation,account,numberOfNodes,nodeType,starttime,endtime,headers):
	url = RESERVATIONS_URL
	headers["X-Machine-Name"] = system
	data = {"reservation":reservation,"account":account,"numberOfNodes":numberOfNodes,"nodeType":nodeType,"starttime":starttime,"endtime":endtime}
	resp = requests.post(url, headers=headers, data=data , verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	print(resp.headers)
	assert resp.status_code == status_code


@pytest.mark.parametrize("system,status_code,reservation,numberOfNodes,nodeType,starttime,endtime",PUT_DATA)
def test_put_reservation(system, status_code,reservation,numberOfNodes,nodeType,starttime,endtime,headers):
	url = f"{RESERVATIONS_URL}/{reservation}"
	headers["X-Machine-Name"] = system
	data = {"numberOfNodes":numberOfNodes,"nodeType":nodeType,"starttime":starttime,"endtime":endtime}
	resp = requests.put(url, headers=headers, data=data , verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	print(resp.headers)
	assert resp.status_code == status_code


@pytest.mark.parametrize("system,status_code,reservation",DELETE_DATA)
def test_delete_reservation(system, status_code,reservation,headers):
	url = f"{RESERVATIONS_URL}/{reservation}"
	headers["X-Machine-Name"] = system

	resp = requests.delete(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
	print(resp.content)
	print(resp.headers)
	assert resp.status_code == status_code



if __name__ == '__main__':
	pytest.main()
