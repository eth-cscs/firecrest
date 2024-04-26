#
#  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import firecrest as fc
import os
import time
import argparse
import utilities as util


final_slurm_states = {
    'BOOT_FAIL',
    'CANCELLED',
    'COMPLETED',
    'DEADLINE',
    'FAILED',
    'NODE_FAIL',
    'OUT_OF_MEMORY',
    'PREEMPTED',
    'TIMEOUT',
}

# Setup variables of the client
CLIENT_ID = os.environ.get("FIRECREST_CLIENT_ID")
CLIENT_SECRET = os.environ.get("FIRECREST_CLIENT_SECRET")
FIRECREST_URL = os.environ.get("FIRECREST_URL")
AUTH_TOKEN_URL = os.environ.get("AUTH_TOKEN_URL")


parser = argparse.ArgumentParser()
parser.add_argument("--system", default=os.environ.get('MACHINE'), help="choose system to run")
parser.add_argument("--branch", default="main", help="branch to be tested")
parser.add_argument("--account", default="csstaff", help="branch to be tested")
parser.add_argument("--repo", help="repository to be tested")

args = parser.parse_args()
system_name = args.system
ref = args.branch
print(f"Will try to run the ci in system {system_name} on branch {ref}")

keycloak = fc.ClientCredentialsAuth(CLIENT_ID, CLIENT_SECRET, AUTH_TOKEN_URL)
client = fc.Firecrest(firecrest_url=FIRECREST_URL, authorization=keycloak)

print(client.all_systems())
script_content = util.create_batch_script(repo=args.repo, constraint='gpu', num_nodes=2, account=args.account, custom_modules=['cray-python'], branch=ref)
with open("submission_script.sh", "w") as fp:
    fp.write(script_content)

system_state = client.system(system_name)
print(f'Status of system is: {system_state["status"]}')

if system_state["status"] == "available":
    job = client.submit(system_name, "submission_script.sh")
    print(f"Submitted job: {job['jobid']}")
    poll_result = client.poll_active(system_name, jobs=[job["jobid"]])
    while poll_result:
        state = poll_result[0]["state"]
        if state in final_slurm_states:
            print(f"Job is in final state: {state}")
            break

        print(f"Status of the job is {poll_result[0]['state']}, will try again in 10 seconds")
        time.sleep(10)
        poll_result = client.poll_active(system_name, jobs=[job["jobid"]])

    if not poll_result:
        print("The job is no longer active")

    print(f"\nSTDOUT in {job['job_file_out']}")
    stdout_content = client.head(system_name, job['job_file_out'], lines=100)
    print(stdout_content)

    print(f"\nSTDERR in {job['job_file_err']}")
    stderr_content = client.head(system_name, job['job_file_err'], lines=100)
    print(stderr_content)

    # Some sanity checks:
    poll_result = client.poll(system_name, jobs=[job["jobid"]])
    if poll_result[0]["state"] != "COMPLETED":
        print(f"Job was not successful, status: {poll_result[0]['state']}")
        exit(1)

    util.check_output(stdout_content)

else:
    print("System {system_name} is not available")
    exit(1)
