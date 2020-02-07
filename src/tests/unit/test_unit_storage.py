#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import pytest
import requests

STORAGE_URL = "http://0.0.0.0:5002"

# test upload request: ask for an upload task (must throw 200 OK), and then
# inform upload complete (must throw 400 since upload has not been done)
def test_post_upload_request(headers):
    data = { "sourcePath": "testsbatch.sh", "targetPath": "testsbatch.sh" }
    resp = requests.post(STORAGE_URL + "/xfer-external/upload", headers=headers, data=data)
    assert resp.status_code == 200

    task_id = resp.json()["task_id"]
    headers.update({"X-Task-ID": task_id})
    r = requests.put(STORAGE_URL + "/xfer-external/upload", headers=headers)
    assert r.status_code == 400

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

