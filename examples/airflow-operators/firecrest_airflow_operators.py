#
#  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import os
import tempfile
import time

import firecrest as f7t
from airflow.models.baseoperator import BaseOperator
from airflow import AirflowException

# Workaround to run tasks that do http request from the Airflow UI
# https://github.com/apache/airflow/discussions/24463#discussioncomment-4404542
# Other discussions on the topic:
# https://stackoverflow.com/questions/75980623/why-is-my-airflow-hanging-up-if-i-send-a-http-request-inside-a-task
import platform


if platform.processor() == 'arm' and platform.system() == 'Darwin':
    from _scproxy import _get_proxy_settings
    _get_proxy_settings()

#


class FirecRESTBaseOperator(BaseOperator):
    firecrest_url = os.environ['FIRECREST_URL']
    client_id = os.environ['FIRECREST_CLIENT_ID']
    client_secret = os.environ['FIRECREST_CLIENT_SECRET']
    token_uri = os.environ['AUTH_TOKEN_URL']

    keycloak = f7t.ClientCredentialsAuth(
        client_id, client_secret, token_uri
    )

    client = f7t.Firecrest(firecrest_url=firecrest_url, authorization=keycloak)


class FirecRESTSubmitOperator(FirecRESTBaseOperator):
    """Airflow Operator to submit a job via FirecREST"""

    def __init__(self, system: str, script: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.system = system
        self.script = script

    def execute(self, context):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(bytes(self.script, 'utf-8'))
            tmp.seek(0)
            job = self.client.submit(self.system, tmp.name)
            time.sleep(10)

        while True:
            if self.client.poll_active(self.system, [job['jobid']]) == []:
                break

            time.sleep(10)

        job_info = self.client.poll(self.system, [job['jobid']])
        if job_info[0]['state'] != 'COMPLETED':
            raise AirflowException(f"Job state: {job_info[0]['state']}")

        return job


class FirecRESTDownloadOperator(FirecRESTBaseOperator):
    """Airflow Operator to fetch the output file of a job
    submitted via FirecREST"""

    def __init__(self,
                 system: str,
                 local_path: str,
                 target_task_id: str,
                 **kwargs) -> None:
        super().__init__(**kwargs)
        self.system = system
        self.local_path = local_path
        self.target_task_id = target_task_id

    def execute(self, context):
        job = context["ti"].xcom_pull(key="return_value",
                                      task_ids=self.target_task_id)
        # download job's output
        self.client.simple_download(self.system, job['job_file_out'],
                                    self.local_path)


class FirecRESTUploadOperator(FirecRESTBaseOperator):
    """Airflow Operator to updload the input file for a job
    to be submitted via FirecREST later in the DAG"""

    def __init__(self,
                 system: str,
                 source_path: str,
                 target_path: str,
                 **kwargs) -> None:
        super().__init__(**kwargs)
        self.system = system
        self.source_path = source_path
        self.target_path = target_path

    def execute(self, context):
        self.client.simple_upload(self.system, self.source_path,
                                  self.target_path)
