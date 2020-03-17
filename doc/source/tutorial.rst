========
Tutorial
========

Obtain credentials
==================

After obtaining the credentials set these variables:

.. tabs::

    .. code-tab:: bash

        $ export TOKEN=<token>
        $ export FIRECREST_IP="localhost:8000"
        $ export STORAGE_IP="localhost:9000"

    .. code-tab:: python

        TOKEN = <token>
        FIRECREST_IP = 'localhost:8000'
        STORAGE_IP = 'localhost:9000'

Test the credentials with a simple call
=======================================

.. tabs::

    .. code-tab:: bash

        $ curl -X GET ${FIRECREST_IP}/status/services -H "Authorization: Bearer ${TOKEN}"

    .. code-tab:: python

        url = f'{FIRECREST_IP}/status/services'
        headers = {'Authorization': f'Bearer {TOKEN}'}
        response = requests.get(url=url, headers=headers)

**Example response**:

.. code-block::

    {
        "description": "List of services with status and description.",
        "out": [
            {
                "description": "server up & flask running",
                "service": "certificator",
                "status": "available"
            },
            {
                "description": "server up & flask running",
                "service": "utilities",
                "status": "available"
            },
            {
                "description": "server up & flask running",
                "service": "tasks",
                "status": "available"
            },
            {
                "description": "server up & flask running",
                "service": "compute",
                "status": "available"
            },
            {
                "description": "server up & flask running",
                "service": "storage",
                "status": "available"
            }
        ]
    }


List the contents of a directory
================================

.. tabs::

    .. code-tab:: bash

        $ curl -X GET "${FIRECREST_IP}/utilities/ls?targetPath=/home/test1" -H "Authorization: Bearer ${TOKEN}" -H "X-Machine-Name: cluster"

    .. code-tab:: python

        path = '/home/test1
        url = f'{FIRECREST_IP}/utilities/ls'
        headers = {'Authorization': f'Bearer {TOKEN}',
                   'X-Machine-Name': 'cluster'}
        params = {'targetPath': f'{path}'}
        response = requests.get(url=url, headers=headers, params=params)

**Example response**:

.. code-block::

    {
        "descr": "List of contents of path",
        "output": [
            {
                "group": "test1",
                "last_modified": "2020-03-13T13:15:48",
                "link_target": "",
                "name": "new-dir",
                "permissions": "rwxrwxr-x",
                "size": "4096",
                "type": "d",
                "user": "test1"
            },
            {
                "group": "test1",
                "last_modified": "2020-03-13T12:52:44",
                "link_target": "",
                "name": "test_file.txt",
                "permissions": "rw-rw-r--",
                "size": "247",
                "type": "-",
                "user": "test1"
            }
        ]
    }

Upload with blocking call a small file
======================================

Upload batch script
^^^^^^^^^^^^^^^^^^^

.. tabs::

    .. code-tab:: bash

        $ curl -X POST "${FIRECREST_IP}/utilities/upload" -F "targetPath=/home/test1" -H "Authorization: Bearer $TOKEN" -H "X-Machine-Name: cluster" -F "file=@/path/to/script.sh"

    .. code-tab:: python

        targetPath = '/home/test1'
        url = f'{FIRECREST_IP}/utilities/upload'
        headers={'Authorization': f'Bearer {TOKEN}',
                 'X-Machine-Name': 'cluster'}
        data={'targetPath': targetPath}
        files={'file': open(local_path,"rb")}
        response = requests.post(
                url=url,
                headers=headers,
                data=data,
                files=files
            )

**Example response**:

.. sourcecode::

    {
        "description": "File upload successful"
    }

Upload small input
^^^^^^^^^^^^^^^^^^

Run a small simulation
======================

Submit job
^^^^^^^^^^

.. tabs::

    .. code-tab:: bash

        $ curl -X POST "${FIRECREST_IP}/compute/jobs" -F "targetPath=/home/test1" -H "Authorization: Bearer $TOKEN" -H "X-Machine-Name: cluster" -F "file=@/path/to/script.sh"

    .. code-tab:: python

        wip

**Example response**:

.. sourcecode::

    {
        "success": "Task created",
        "task_id": "9d9c69b640cfd1cccffb76e1b7297a98",
        "task_url": "http://192.168.220.10:8000/tasks/9d9c69b640cfd1cccffb76e1b7297a98"
    }


And then you can get the job id from this job with this call.


.. tabs::

    .. code-tab:: bash

        $ curl -X GET "${FIRECREST_IP}/tasks/9d9c69b640cfd1cccffb76e1b7297a98" -H "Authorization: Bearer $TOKEN" -H "X-Machine-Name: cluster"

    .. code-tab:: python

        wip

**Example response**:

.. sourcecode::

    {
        "task": {
            "data": {
                "jobid": 3,
                "result": "Job submitted"
            },
            "description": "Finished successfully",
            "hash_id": "39c2ed7cdb4067948b6da516b8d3249a",
            "last_modify": "2020-03-15T17:59:43",
            "service": "compute",
            "status": "200",
            "task_url": "http://192.168.220.10:8000/tasks/39c2ed7cdb4067948b6da516b8d3249a",
            "user": "test1"
        }
    }


Check for job status
^^^^^^^^^^^^^^^^^^^^

You can get the current status of job with these two calls:

.. tabs::

    .. code-tab:: bash

        curl -X GET "${FIRECREST_IP}/compute/jobs/3" -F "targetPath=/home/test1" -H "Authorization: Bearer $TOKEN" -H "X-Machine-Name: cluster"

    .. code-tab:: python

        wip


.. sourcecode::

    {
        "success": "Task created",
        "task_id": "babda2e02fc654f4e2513595525e4fb4",
        "task_url": "http://192.168.220.10:8000/tasks/babda2e02fc654f4e2513595525e4fb4"
    }

Use the task_id you got from the previous call or even the task url that is provided.

.. tabs::

    .. code-tab:: bash

        curl -X GET "${FIRECREST_IP}/tasks/babda2e02fc654f4e2513595525e4fb4" -H "Authorization: Bearer $TOKEN" -H "X-Machine-Name: cluster"

    .. code-tab:: python

        wip

While running the call will be successful

.. sourcecode::

    {
        "task": {
            "data": {
                "0": {
                    "jobid": "5",
                    "name":"script.sh",
                    "nodelist":"cluster",
                    "nodes":"1",
                    "partition":"part01",
                    "start_time":"4:14",
                    "state":"RUNNING",
                    "time":"2020-03-17T09:08:01",
                    "time_left":"25:46",
                    "user":"test1"
                }
            },
            "description":"Finished successfully",
            "hash_id":"49827d8d914e07c303eb40d55ede552a",
            "last_modify":"2020-03-17T09:12:15",
            "service":"compute",
            "status":"200",
            "task_url":"http://192.168.220.10:8000/tasks/49827d8d914e07c303eb40d55ede552a",
            "user":"test1"
        }
    }

But after the job has finished for some time you will get something like this:

.. sourcecode::

    {
        "task": {
            "data": "slurm_load_jobs error: Invalid job id specified",
            "description": "Finished with errors",
            "hash_id": "2a3a5e35008b6da1df8b27cb0089aaed",
            "last_modify": "2020-03-15T18:05:54",
            "service": "compute",
            "status": "400",
            "task_url": "http://192.168.220.10:8000/tasks/2a3a5e35008b6da1df8b27cb0089aaed",
            "user":"test1"
        }
    }

This call uses squeue so it doesn't have information for old jobs.


**Sacct call**

Persistent accounting information

.. tabs::

    .. code-tab:: bash

        curl -X GET "${FIRECREST_IP}/compute/acct" -H "Authorization: Bearer $TOKEN" -H "X-Machine-Name: cluster"

    .. code-tab:: python

        wip

.. sourcecode::

    {
        "task": {
            "data": [
                {
                    "jobid":"4",
                    "name":"script.sh",
                    "nodelist":"cluster",
                    "nodes":"1",
                    "partition":"part01",
                    "start_time":"2020-03-17T08:44:58",
                    "state":"COMPLETED",
                    "time":"00:02:00",
                    "time_left":"2020-03-17T08:45:58",
                    "user":"test1"
                },
                {
                    "jobid":"5",
                    "name":"script_long.sh",
                    "nodelist":"cluster",
                    "nodes":"1",
                    "partition":"part01",
                    "start_time":"2020-03-17T09:08:01",
                    "state":"COMPLETED",
                    "time":"00:10:00",
                    "time_left":"2020-03-17T09:13:01",
                    "user":"test1"
                },
                {
                    "jobid":"6",
                    "name":"script_long.sh",
                    "nodelist":"cluster",
                    "nodes":"1",
                    "partition":"part01",
                    "start_time":"2020-03-17T09:41:42",
                    "state":"COMPLETED",
                    "time":"00:10:00",
                    "time_left":"2020-03-17T09:46:42",
                    "user":"test1"
                }
            ],
            "description":"Finished successfully",
            "hash_id":"8e793227fdf57789d2b43bddca65d3a2",
            "last_modify":"2020-03-17T10:00:26",
            "service":"compute",
            "status":"200",
            "task_url":"http://192.168.220.10:8000/tasks/8e793227fdf57789d2b43bddca65d3a2",
            "user": "test1"
        }
    }

You can also get accounting information for a specific period of time or job id.

Upload with non blocking call something bigger
==============================================

First upload the file to storage. targetPath is local, sourcePath is on the machine.

.. tabs::

    .. code-tab:: bash

        curl -X POST "${FIRECREST_IP}/storage/xfer-external/upload" -H "Authorization: Bearer $TOKEN" -H "X-Machine-Name: cluster" -F "sourcePath=/path/to/script.sh" -F "targetPath=/home/test1/new-dir"

    .. code-tab:: python

        wip

.. sourcecode::

    {
        "success": "Task created",
        "task_id": "a78c226e2e17ea05ef1d72a812648145",
        "task_url": "http://192.168.220.10:8000/tasks/a78c226e2e17ea05ef1d72a812648145"
    }

.. tabs::

    .. code-tab:: bash

        curl -X GET "${FIRECREST_IP}/tasks/a78c226e2e17ea05ef1d72a812648145" -H "Authorization: Bearer $TOKEN" -H "X-Machine-Name: cluster"

    .. code-tab:: python

        wip

.. sourcecode::

    {
        "task": {
            "data": {
                "hash_id": "a78c226e2e17ea05ef1d72a812648145",
                "msg": {
                    "command": "curl -i -X POST http://192.168.220.19:9000/test1 -F 'key=a78c226e2e17ea05ef1d72a812648145/script.sh' -F 'x-amz-algorithm=AWS4-HMAC-SHA256' -F 'x-amz-credential=storage_access_key/20200317/us-east-1/s3/aws4_request' -F 'x-amz-date=20200317T140011Z' -F 'policy=eyJleHBpcmF0aW9uIjogIjIwMjAtMDMtMjRUMTQ6MDA6MTFaIiwgImNvbmRpdGlvbnMiOiBbeyJidWNrZXQiOiAidGVzdDEifSwgeyJrZXkiOiAiYTc4YzIyNmUyZTE3ZWEwNWVmMWQ3MmE4MTI2NDgxNDUvc2NyaXB0LnNoIn0sIHsieC1hbXotYWxnb3JpdGhtIjogIkFXUzQtSE1BQy1TSEEyNTYifSwgeyJ4LWFtei1jcmVkZW50aWFsIjogInN0b3JhZ2VfYWNjZXNzX2tleS8yMDIwMDMxNy91cy1lYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0sIHsieC1hbXotZGF0ZSI6ICIyMDIwMDMxN1QxNDAwMTFaIn1dfQ==' -F 'x-amz-signature=955f64c020ebc4b797fac7d4338ee695c5c9605dc9962a135df57a23c4423aab' -F file=@/path/to/script.sh",
                    "key": "a78c226e2e17ea05ef1d72a812648145/script.sh",
                    "method": "POST",
                    "policy": "eyJleHBpcmF0aW9uIjogIjIwMjAtMDMtMjRUMTQ6MDA6MTFaIiwgImNvbmRpdGlvbnMiOiBbeyJidWNrZXQiOiAidGVzdDEifSwgeyJrZXkiOiAiYTc4YzIyNmUyZTE3ZWEwNWVmMWQ3MmE4MTI2NDgxNDUvc2NyaXB0LnNoIn0sIHsieC1hbXotYWxnb3JpdGhtIjogIkFXUzQtSE1BQy1TSEEyNTYifSwgeyJ4LWFtei1jcmVkZW50aWFsIjogInN0b3JhZ2VfYWNjZXNzX2tleS8yMDIwMDMxNy91cy1lYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0sIHsieC1hbXotZGF0ZSI6ICIyMDIwMDMxN1QxNDAwMTFaIn1dfQ==",
                    "url": "http://192.168.220.19:9000/test1",
                    "x-amz-algorithm": "AWS4-HMAC-SHA256",
                    "x-amz-credential": "storage_access_key/20200317/us-east-1/s3/aws4_request",
                    "x-amz-date": "20200317T140011Z",
                    "x-amz-signature": "955f64c020ebc4b797fac7d4338ee695c5c9605dc9962a135df57a23c4423aab"
                },
                "source": "script.sh",
                "system": "192.168.220.12:22",
                "target": "/home/test1/new-dir",
                "user": "test1"
            },
            "description": "Form URL from Object Storage received",
            "hash_id": "a78c226e2e17ea05ef1d72a812648145",
            "last_modify": "2020-03-17T14:00:11",
            "service": "storage",
            "status": "111",
            "task_url": "http://192.168.220.10:8000/tasks/a78c226e2e17ea05ef1d72a812648145",
            "user": "test1"
        }
    }

Then the file should be uploaded with the command from the previous request:

.. tabs::

    .. code-tab:: bash

        curl -i -X POST "${STORAGE_IP}/test1" -F 'key=a78c226e2e17ea05ef1d72a812648145/script.sh' -F 'x-amz-algorithm=AWS4-HMAC-SHA256' -F 'x-amz-credential=storage_access_key/20200317/us-east-1/s3/aws4_request' -F 'x-amz-date=20200317T140011Z' -F 'policy=eyJleHBpcmF0aW9uIjogIjIwMjAtMDMtMjRUMTQ6MDA6MTFaIiwgImNvbmRpdGlvbnMiOiBbeyJidWNrZXQiOiAidGVzdDEifSwgeyJrZXkiOiAiYTc4YzIyNmUyZTE3ZWEwNWVmMWQ3MmE4MTI2NDgxNDUvc2NyaXB0LnNoIn0sIHsieC1hbXotYWxnb3JpdGhtIjogIkFXUzQtSE1BQy1TSEEyNTYifSwgeyJ4LWFtei1jcmVkZW50aWFsIjogInN0b3JhZ2VfYWNjZXNzX2tleS8yMDIwMDMxNy91cy1lYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0sIHsieC1hbXotZGF0ZSI6ICIyMDIwMDMxN1QxNDAwMTFaIn1dfQ==' -F 'x-amz-signature=955f64c020ebc4b797fac7d4338ee695c5c9605dc9962a135df57a23c4423aab' -F file=@/path/to/script.sh

    .. code-tab:: python

        wip

.. sourcecode::

    HTTP/1.1 100 Continue

    HTTP/1.1 204 No Content
    Accept-Ranges: bytes
    Content-Security-Policy: block-all-mixed-content
    ETag: "b7461b9179ab9119848121d810ba2ff2-1"
    Location: http://localhost:9000/test1/a78c226e2e17ea05ef1d72a812648145/script.sh
    Server: MinIO/RELEASE.2020-03-09T18-26-53Z
    Vary: Origin
    X-Amz-Request-Id: 15FD1C504742F8A8
    X-Xss-Protection: 1; mode=block
    Date: Tue, 17 Mar 2020 14:02:55 GMT

Finish the upload

.. tabs::

    .. code-tab:: bash

        curl -X PUT "${FIRECREST_IP}/storage/xfer-external/upload" -H "Authorization: Bearer $TOKEN" -H "X-Machine-Name: cluster" -H "X-Task-ID: a78c226e2e17ea05ef1d72a812648145"

    .. code-tab:: python

        wip

.. sourcecode::

    {
        "success": "Starting download to File System"
    }

You can check again the task and when you get something like this it will be finished

.. tabs::

    .. code-tab:: bash

        curl -X GET "${FIRECREST_IP}/tasks/a78c226e2e17ea05ef1d72a812648145" -H "Authorization: Bearer $TOKEN" -H "X-Machine-Name: cluster"

    .. code-tab:: python

        wip

.. sourcecode::

    {
        "task": {
            "data": {
                "hash_id": "a78c226e2e17ea05ef1d72a812648145",
                "msg": "Starting async task for download to filesystem",
                "source": "script.sh",
                "system": "192.168.220.12:22",
                "target": "/home/test1/new-dir",
                "user": "test1"
            },
            "description": "Download from Object Storage to server has finished",
            "hash_id": "a78c226e2e17ea05ef1d72a812648145",
            "last_modify": "2020-03-17T14:04:52",
            "service": "storage",
            "status": "114",
            "task_url": "http://192.168.220.10:8000/tasks/a78c226e2e17ea05ef1d72a812648145",
            "user": "test1"
        }
    }

Run again the simulation with a bigger file
===========================================

Same as the other submission, to be filled when we have a use case

Download the output
===================

First you have to start the uploading from the machine's filesystem to object storage

.. tabs::

    .. code-tab:: bash

        curl -X POST "${FIRECREST_IP}/storage/xfer-external/download" -H "Authorization: Bearer $TOKEN" -H "X-Machine-Name: cluster" -F "sourcePath=/home/test1/new-dir/script.sh"

    .. code-tab:: python

        wip

.. sourcecode::

    {
        "success":"Task created",
        "task_id":"c958b5901cb7229ef15d9ae0e93e6d8b",
        "task_url":"http://192.168.220.10:8000/tasks/c958b5901cb7229ef15d9ae0e93e6d8b"
    }

.. tabs::

    .. code-tab:: bash

        curl -X GET "${FIRECREST_IP}/tasks/c958b5901cb7229ef15d9ae0e93e6d8b" -H "Authorization: Bearer $TOKEN" -H "X-Machine-Name: cluster"

    .. code-tab:: python

        wip

After it finishes you should get a response like this.

.. sourcecode::

    {
        "task": {
            "data": "http://192.168.220.19:9000/test1/c958b5901cb7229ef15d9ae0e93e6d8b/script.sh?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=storage_access_key%2F20200317%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20200317T141948Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-Amz-Signature=c951b0a4d8a2bcaff5b1eb443f83f37f0718da36e8e59d7b1fa19a1b3a5f3cbf",
            "description": "Upload from filesystem to Object Storage has finished succesfully",
            "hash_id": "c958b5901cb7229ef15d9ae0e93e6d8b",
            "last_modify": "2020-03-17T14:19:48",
            "service": "storage",
            "status": "117",
            "task_url": "http://192.168.220.10:8000/tasks/c958b5901cb7229ef15d9ae0e93e6d8b",
            "user": "test1"
        }
    }

And you can download the file from the link in the "data" field.


Troubleshooting
===============

.. sourcecode::

    {
        "exp": "token expired"
    }
