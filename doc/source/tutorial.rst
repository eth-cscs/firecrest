========
Tutorial
========

Obtain credentials
==================


Test the credentials with a simple call
=======================================

.. tabs::

    .. code-tab:: bash

        $ curl -X GET localhost:8000/status/services -H "Authorization: Bearer <token>"

    .. code-tab:: python

        URL = f'{firecrest_ip}/status/services'
        HEADERS = {'Authorization': f'Bearer {token}'}
        response = requests.get(url=URL, headers=HEADERS)

**Example response**:

.. sourcecode:: json

    {
        'description': 'List of services with status and description.',
        'out': [
            {
                'description': 'server up & flask running',
                'service': 'certificator',
                'status': 'available'
            },
            {
                'description': 'server up & flask running',
                'service': 'tasks',
                'status': 'available'
            },
            {
                'description': 'server up & flask running',
                'service': 'storage',
                'status': 'available'
            },
            {
                'description': 'server up & flask running',
                'service': 'compute',
                'status': 'available'
            },
            {
                'description': 'server up & flask running',
                'service': 'utilities',
                'status': 'available'
            }
        ]
    }


List the contents of a directory
================================

.. tabs::

    .. code-tab:: bash

        $ curl -X GET localhost:8000/utilities/ls?targetPath=/home/test1 -H "Authorization: Bearer <token>" -H "X-Machine-Name: cluster"

    .. code-tab:: python

        URL = f'{firecrest_ip}/utilities/ls'
        HEADERS = {'Authorization': f'Bearer {token}',
                   'X-Machine-Name': 'cluster'}
        PARAMS = {'targetPath': f'{path}'}
        response = requests.get(url=URL, headers=HEADERS, params=PARAMS)

**Example response**:

.. sourcecode:: json

    {
        'descr': 'List of contents of path',
        'output': [
            {
                'group': 'test1',
                'last_modified': '2020-03-12T12:08:45',
                'link_target': '',
                'name': 'new-dir',
                'permissions': 'rwxrwxr-x',
                'size': '4096',
                'type': 'd',
                'user': 'test1'
            },
            {
                'group': 'test1',
                'last_modified': '2020-03-12T12:09:39',
                'link_target': '',
                'name': 'test_file.txt',
                'permissions': 'rw-rw-r--',
                'size': '0',
                'type': '-',
                'user': 'test1'
            }
        ]
    }

Upload with blocking call a small file
======================================

Upload batch script
^^^^^^^^^^^^^^^^^^^

.. tabs::

    .. code-tab:: bash

        $ curl -X POST "localhost:8000/utilities/upload" -F "targetPath=/home/test1" -H "X-Machine-Name: cluster" -F "file=@/path/to/script.sh" -H "Authorization: Bearer <token>"

    .. code-tab:: python

        wip

**Example response**:

.. sourcecode:: json

    {
        'description': 'File upload successful'
    }

Upload small input
^^^^^^^^^^^^^^^^^^

Run a small simulation
======================

Submit job
^^^^^^^^^^

Check for job status
^^^^^^^^^^^^^^^^^^^^

Upload with non blocking call something bigger
==============================================

Run again the simulation with a bigger file
===========================================

Download the output
===================

