#
#  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import pytest
import requests
import os
from test_globals import *
from markers import skipif_not_uses_gateway, skipif_uses_gateway

FIRECREST_URL = os.environ.get("FIRECREST_URL")
USE_GATEWAY  = (os.environ.get("USE_GATEWAY","false").lower() == "true")


if FIRECREST_URL and USE_GATEWAY:
    STORAGE_URL = os.environ.get("FIRECREST_URL") + "/storage"
else:
    STORAGE_URL = os.environ.get("F7T_STORAGE_URL")

### SSL parameters
USE_SSL = os.environ.get("F7T_USE_SSL", False)
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_PATH = "../../../deploy/test-build"

machine = os.environ.get("F7T_SYSTEMS_PUBLIC").strip('\'"').split(";")[0]

# test upload request: ask for an upload task (must throw 200 OK)
@skipif_not_uses_gateway
def test_post_upload_request(headers):
    headers["X-Machine-Name"] = machine
    data = { "sourcePath": "testsbatch.sh", "targetPath": USER_HOME }
    resp = requests.post(STORAGE_URL + "/xfer-external/upload", headers=headers, data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
    assert resp.status_code == 201

@skipif_not_uses_gateway
def test_download_file_not_exist(headers):
    headers["X-Machine-Name"] = machine
    data = { "sourcePath": "no-existing-file" }
    resp = requests.post(STORAGE_URL + "/xfer-external/download", headers=headers, data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
    print(resp.json())
    print(resp.headers)
    assert resp.status_code == 400

@skipif_not_uses_gateway
def test_download_file_not_allowed(headers):
    headers["X-Machine-Name"] = machine
    data = { "sourcePath": "/srv/f7t/test_sbatch_forbidden.sh" }
    resp = requests.post(STORAGE_URL + "/xfer-external/download", headers=headers, data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
    print(resp.json())
    print(resp.headers)
    assert resp.status_code == 400

@skipif_not_uses_gateway
def test_download_dir_not_allowed(headers):
    headers["X-Machine-Name"] = machine
    data = { "sourcePath": "/srv/f7t" }
    resp = requests.post(STORAGE_URL + "/xfer-external/download", headers=headers, data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
    print(resp.json())
    print(resp.headers)
    assert resp.status_code == 400

@skipif_not_uses_gateway
def test_internal_cp(headers):
    headers["X-Machine-Name"] = machine
    data = {"sourcePath":  "/srv/f7t/test_sbatch.sh", "targetPath": USER_HOME + "/testsbatch2.sh", "account": "test"}
    url = f"{STORAGE_URL}/xfer-internal/cp"
    resp = requests.post(url, headers=headers,data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
    assert resp.status_code == 201

@skipif_not_uses_gateway
def test_internal_mv(headers):
    headers["X-Machine-Name"] = machine
    data = {"sourcePath": "/srv/f7t/test_sbatch_mv.sh", "targetPath": USER_HOME + "/testsbatch3.sh"}
    url = f"{STORAGE_URL}/xfer-internal/mv"
    resp = requests.post(url, headers=headers,data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
    assert resp.status_code == 201

@skipif_not_uses_gateway
def test_internal_rsync(headers):
    headers["X-Machine-Name"] = machine
    data = {"sourcePath": USER_HOME + "/", "targetPath": USER_HOME + "/"}
    url = f"{STORAGE_URL}/xfer-internal/rsync"
    resp = requests.post(url, headers=headers,data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
    assert resp.status_code == 201

@skipif_not_uses_gateway
def test_internal_rm(headers):
    headers["X-Machine-Name"] = machine
    data = {"targetPath": "/srv/f7t/test_sbatch_rm.sh"}
    url = f"{STORAGE_URL}/xfer-internal/rm"
    resp = requests.post(url, headers=headers,data=data, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
    assert resp.status_code == 201

# Test storage microservice status
@skipif_uses_gateway
def test_status(headers):
    url = f"{STORAGE_URL}/status"
    resp = requests.get(url, headers=headers, verify= (f"{SSL_PATH}{SSL_CRT}" if USE_SSL else False))
    assert resp.status_code == 200


if __name__ == '__main__':
	pytest.main()
