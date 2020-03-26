========
Tutorial
========

In this section, we will learn how to interact with the FirecREST's API through HTTP GET/POST/PUT/DELETE calls.
The examples will be provided both in the form of a curl command and python code.
The curl command will give you a more direct understanding of the parameters of each call and hopefully make it easier to try yourself, while the python code could be the base for a simple client, like the one that is developed `here <https://github.com/eth-cscs/firecrest/tree/master/deploy/demo>`_.

The tutorial follows the following workflow:

- Obtaining the necessary credentials
- Checking for the available systems
- Uploading the input data to the machine's filesystem
- Run a simulation
- Upload a bigger file
- Run again the simulation
- Download the results
- Verify results

Obtain credentials
==================

All the requests in the FirecREST API require authorization.
The access token allows you to make requests on behalf of the authenticated user.
The token is provided by `Keycloak <https://www.keycloak.org//>`_ and it has to be included in the header of all the API calls.
You should also keep in mind that validation tokens usually have an expiration date and are short-lived.

FirecREST API will return helpful messages in case the access token is invalid or has expired.

**Invalid token**:

.. code-block:: json

    {
        "message": "Bad token; invalid JSON"
    }

**Expired token**:

.. code-block:: json

    {
        "exp": "token expired"
    }

After obtaining the credentials you have to set these variables:

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

To test the credentials we can use a simple call from the `Status microservice <overview.html#status>`__.
We can call the `firecrest/status/services <reference.html#get--status-services>`__ endpoint with a *GET* operation to get the status of all the services.
The access token has to be included in the header.

.. tabs::

    .. code-tab:: bash

        $ curl -X GET ${FIRECREST_IP}/status/services -H "Authorization: Bearer ${TOKEN}"

    .. code-tab:: python

        url = f'{FIRECREST_IP}/status/services'
        headers = {'Authorization': f'Bearer {TOKEN}'}
        response = requests.get(url=url, headers=headers)

The response to this call will look something like:

.. code-block:: json

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

Another simple but useful call of the API is the listing of the contents of a directory.
As before we have to include the authorization token in the header but we also have to specify the machine name's filesystem and the directory we want to list.
In our example the machine is *cluster* and we want to list our home directory, */home/test1*.
As we can see in the reference section of `utilities/ls <reference.html#get--utilities-ls>`__, the machine name is also part of the header but the target path is a query parameter.

.. note::
    Query parameters are passed in the `params` argument in python but are part of the URL in the curl command.

Finally the call looks like this:

.. tabs::

    .. code-tab:: bash

        $ curl -X GET "${FIRECREST_IP}/utilities/ls?targetPath=/home/test1" -H "Authorization: Bearer ${TOKEN}" -H "X-Machine-Name: cluster"

    .. code-tab:: python

        path = '/home/test1
        machine = 'cluster'
        response = requests.get(
            url=f'{FIRECREST_IP}/utilities/ls',
            headers={'Authorization': f'Bearer {TOKEN}',
                     'X-Machine-Name': machine},
            params={'targetPath': f'{path}'}
        )

And the response should look something like:

.. code-block:: json

    {
        "descr": "List of contents of path",
        "output": [
            {
                "group": "test1",
                "last_modified": "2020-03-17T09:41:42",
                "link_target": "",
                "name": "firecrest",
                "permissions": "rwxrwxr-x",
                "size": "4096",
                "type": "d",
                "user": "test1"
            },
            {
                "group": "test1",
                "last_modified": "2020-03-17T14:04:51",
                "link_target": "",
                "name": "new-dir",
                "permissions": "rwxrwxr-x",
                "size": "4096",
                "type": "d",
                "user": "test1"
            },
            {
                "group": "test1",
                "last_modified": "2020-03-25T17:35:24",
                "link_target": "",
                "name": "test_file.txt",
                "permissions": "rw-rw-r--",
                "size": "222",
                "type": "-",
                "user": "test1"
            }
        ]
    }

When the call is successful the body of the response is enough, but in case we get an error the response header can give us more information about the error.

.. note::
    To get the response header in the curl command add `-i` in the call.

In case we ask to list a directory in which the user doesn't have the right permissions we will get `X-Permission-Denied: User does not have permissions to access machine or path`.

.. code-block:: none

    HTTP/1.1 400 BAD REQUEST
    Content-Type: application/json
    Content-Length: 49
    Connection: keep-alive
    X-Permission-Denied: User does not have permissions to access machine or path
    Server: Werkzeug/1.0.0 Python/3.6.8
    Date: Tue, 24 Mar 2020 09:21:03 GMT
    X-Kong-Upstream-Latency: 168
    X-Kong-Proxy-Latency: 2
    Via: kong/2.0.2

    {
        "description": "Error listing contents of path"
    }

But when we try to list a directory that doesn't exist the error would be different in the header.

.. code-block:: none

    HTTP/1.1 400 BAD REQUEST
    Content-Type: application/json
    Content-Length: 49
    Connection: keep-alive
    X-Invalid-Path: /home/test23 is an invalid path
    Server: Werkzeug/1.0.0 Python/3.6.8
    Date: Tue, 24 Mar 2020 09:27:44 GMT
    X-Kong-Upstream-Latency: 172
    X-Kong-Proxy-Latency: 2
    Via: kong/2.0.2

    {
        "description": "Error listing contents of path"
    }

In the reference section of `utilities/ls <reference.html#get--utilities-ls>`__ you can see more error types you can get in the response header.

The `demo client <https://github.com/eth-cscs/firecrest/tree/master/src/tests/template_client>`__ uses the json response and displays the contents of a directory in a more user friendly way, as shown in the next figure.

.. figure:: ../_static/img/utilities.png

Upload a small file with the blocking call
==========================================

The first step of our workflow is to upload the necessary files to one of the machines' filesystems.
Many times the input can be a small file and for these cases the non blocking call `utilities/upload <reference.html#post--utilities-upload>`__ should be enough.
As before, we need to specify the machine and the authorization token in the header of the call, as well as some the location of the file we want to upload and the location in the machine.
The path to the file corresponds to a local path, while targetPath is in the machine.

.. note::
    Notice that `targetPath` is not a query parameter like in `utilities/ls`, but form data. In the curl command we have to use `-F "targetPath=/home/test1"` and in python it is part of the `data` dictionary.

.. tabs::

    .. code-tab:: bash

        $ curl -X POST "${FIRECREST_IP}/utilities/upload" -F "targetPath=/home/test1" -H "Authorization: Bearer $TOKEN" -H "X-Machine-Name: cluster" -F "file=@/path/to/input_file"

    .. code-tab:: python

        targetPath = '/home/test1'
        machine = 'cluster'
        local_path = '/path/to/input_file'
        response = requests.post(
            url=f"{app.config['FIRECREST_IP']}/utilities/upload",
            headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                     'X-Machine-Name': machine},
            data={'targetPath': targetPath},
            files={'file': open(local_path,"rb")}
        )

As we already mentioned this call is blocking, so it will finish when the uploading completes or if it fails. For a successful uploading the body of the response will look like this:

.. code-block:: json

    {
        "description": "File upload successful"
    }

In case the `targetPath` is wrong or the user doesn't have the right permissions for the target location the response will look like this:

.. code-block:: none

    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
    <title>500 Internal Server Error</title>
    <h1>Internal Server Error</h1>
    <p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>


Run a small simulation
======================

Submit job
^^^^^^^^^^

Before submiting our first job it is important to distinguish between two IDs, slurm's `job ID` and FirecREST's `task ID`.
On a job scheduler like Slurm, every job has a unique `job ID`, which is created when a job is submitted and can be used to track the state of the job.
With calls like `squeue` and `sacct` the user can see the state of the job (`RUNNING`, `COMPLETED` etc) as well as get information for the job.
Similarly, for every task FirecREST will assign a `task ID` with which the user can track the state of the request and get information about it.

The first step to submit a job is to make a `POST` request in the `compute/jobs <reference.html#post--compute-jobs>`__  endpoint.
Again, we have to pass the authorization token and the machine in the header.
The file this time will be the script we want to run with slurm.

.. tabs::

    .. code-tab:: bash

        $ curl -X POST "${FIRECREST_IP}/compute/jobs" -H "Authorization: Bearer $TOKEN" -H "X-Machine-Name: cluster" -F "file=@/path/to/script.sh"

    .. code-tab:: python

        wip

The response should like like this:

.. code-block:: json

    {
        "success": "Task created",
        "task_id": "9d9c69b640cfd1cccffb76e1b7297a98",
        "task_url": "http://192.168.220.10:8000/tasks/9d9c69b640cfd1cccffb76e1b7297a98"
    }

.. note::
    You have to keep in mind the `task_id` is **not** Slurm's `job ID` but an ID for the task that was created with FirecREST and we will use that to keep track of the job submitted request.

So to get the status of the job that we submitted we have to make a `GET` call in the `/tasks/{taskid} <reference.html#post--tasks-taskid>`__  endpoint.

.. tabs::

    .. code-tab:: bash

        $ curl -X GET "${FIRECREST_IP}/tasks/9d9c69b640cfd1cccffb76e1b7297a98" -H "Authorization: Bearer $TOKEN"

    .. code-tab:: python

        wip

The response should look like this if the job submission was successful:

.. code-block:: json

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


.. code-block:: json

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

.. code-block:: json

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

.. code-block:: json

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

.. code-block:: json

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

.. code-block:: json

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

.. code-block:: json

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

.. code-block:: bash

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

.. code-block:: json

    {
        "success": "Starting download to File System"
    }

You can check again the task and when you get something like this it will be finished

.. tabs::

    .. code-tab:: bash

        curl -X GET "${FIRECREST_IP}/tasks/a78c226e2e17ea05ef1d72a812648145" -H "Authorization: Bearer $TOKEN" -H "X-Machine-Name: cluster"

    .. code-tab:: python

        wip

.. code-block:: json

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

.. code-block:: json

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

.. code-block:: json

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

.. code-block:: json

    {
        "exp": "token expired"
    }
