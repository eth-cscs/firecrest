#
#  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from flask import Flask, request, jsonify, g
import threading
import async_task
from cscs_api_common import check_auth_header, get_username, \
    exec_remote_command, create_task, update_task, clean_err_output, \
    in_str, is_valid_file, get_boolean_var, validate_input, setup_logging

import logging
import time

from math import ceil
import os
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

import jwt
from flask_opentracing import FlaskTracing
from jaeger_client import Config
import opentracing

from schedulers import Job

AUTH_HEADER_NAME = 'Authorization'

CERTIFICATOR_URL= os.environ.get("F7T_CERTIFICATOR_URL")
TASKS_URL       = os.environ.get("F7T_TASKS_URL")
KONG_URL        = os.environ.get("F7T_KONG_URL")

COMPUTE_PORT    = os.environ.get("F7T_COMPUTE_PORT", 5000)

### SSL parameters
USE_SSL = get_boolean_var(os.environ.get("F7T_USE_SSL", False))
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_KEY = os.environ.get("F7T_SSL_KEY", "")


# SYSTEMS_PUBLIC: list of allowed systems
# remove quotes and split into array
SYSTEMS_PUBLIC  = os.environ.get("F7T_SYSTEMS_PUBLIC").strip('\'"').split(";")
# internal machines to submit/query jobs
SYS_INTERNALS   = os.environ.get("F7T_SYSTEMS_INTERNAL_COMPUTE").strip('\'"').split(";")

# Does the job machine have the spank plugin
USE_SPANK_PLUGIN = os.environ.get("F7T_USE_SPANK_PLUGIN", None)
if USE_SPANK_PLUGIN != None:
    USE_SPANK_PLUGIN = USE_SPANK_PLUGIN.strip('\'"').split(";")
    # cast to boolean
    for i in range(len(USE_SPANK_PLUGIN)):
        USE_SPANK_PLUGIN[i] = get_boolean_var(USE_SPANK_PLUGIN[i])
    # spank plugin option value
    SPANK_PLUGIN_OPTION = os.environ.get("F7T_SPANK_PLUGIN_OPTION","--nohome")
else:
    # if not set, create a list of False values, one for each SYSTEM
    USE_SPANK_PLUGIN = [False]*len(SYS_INTERNALS)


# Filesystems where to save sbatch files
# F7T_FILESYSTEMS = "/home,/scratch;/home"
FILESYSTEMS     = os.environ.get("F7T_FILESYSTEMS").strip('\'"').split(";")
# FILESYSTEMS = ["/home,/scratch", "/home"]

# JOB base Filesystem: ["/scratch";"/home"]
COMPUTE_BASE_FS     = os.environ.get("F7T_COMPUTE_BASE_FS").strip('\'"').split(";")

# Detect scheduler object type
COMPUTE_SCHEDULER = os.environ.get("F7T_COMPUTE_SCHEDULER", "Slurm")

# scopes: get appropiate for jobs/storage, eg:  firecrest-tds.cscs.ch, firecrest-production.cscs.ch
FIRECREST_SERVICE = os.environ.get("F7T_FIRECREST_SERVICE", '').strip('\'"')

TAIL_BYTES = os.environ.get("F7T_TAIL_BYTES",1000)

#max file size for sbatch upload in MB (POST compute/job)
MAX_FILE_SIZE = int(os.environ.get("F7T_UTILITIES_MAX_FILE_SIZE", "5"))
TIMEOUT = int(os.environ.get("F7T_UTILITIES_TIMEOUT", "5"))

TRACER_HEADER = "uber-trace-id"

app = Flask(__name__)
# max content length for upload in bytes
app.config['MAX_CONTENT_LENGTH'] = int(MAX_FILE_SIZE) * 1024 * 1024

debug = get_boolean_var(os.environ.get("F7T_DEBUG_MODE", False))

logger = setup_logging(logging, 'compute')

JAEGER_AGENT = os.environ.get("F7T_JAEGER_AGENT", "").strip('\'"')
if JAEGER_AGENT != "":
    config = Config(
        config={'sampler': {'type': 'const', 'param': 1 },
            'local_agent': {'reporting_host': JAEGER_AGENT, 'reporting_port': 6831 },
            'logging': True,
            'reporter_batch_size': 1},
            service_name = "compute")
    jaeger_tracer = config.initialize_tracer()
    tracing = FlaskTracing(jaeger_tracer, True, app)
else:
    jaeger_tracer = None
    tracing = None

def init_compute():
    global scheduler

    scheduler = None
    if COMPUTE_SCHEDULER == "Slurm":
        app.logger.info("Scheduler selected: Slurm")

        from schedulers.slurm import SlurmScheduler
        scheduler = SlurmScheduler()
    else:
        app.logger.error("No scheduler was set.")


# checks QueuePersistence and retakes all tasks
init_compute()


def get_tracing_headers(req):
    """
    receives a requests object, returns headers suitable for RPC and ID for logging
    """
    new_headers = {}
    if JAEGER_AGENT != "":
        try:
            jaeger_tracer.inject(tracing.get_span(req), opentracing.Format.TEXT_MAP, new_headers)
        except Exception as e:
            app.logger.error(e)

    new_headers[AUTH_HEADER_NAME] = req.headers[AUTH_HEADER_NAME]
    ID = new_headers.get(TRACER_HEADER, '')
    return new_headers, ID

# copies file and submits with sbatch
def submit_job_task(headers, system_name, system_addr, job_file, job_dir, account, use_plugin, task_id):

    try:
        ID = headers.get(TRACER_HEADER, '')
        # create tmpdir for sbatch file
        action = f"ID={ID} timeout {TIMEOUT} mkdir -p -- '{job_dir}'"
        retval = exec_remote_command(headers, system_name, system_addr, action, no_home=use_plugin)

        if retval["error"] != 0:
            app.logger.error(f"(Error creating directory: {retval['msg']}")
            update_task(task_id, headers, async_task.ERROR, retval["msg"])
            return

        if job_file['content']:
            action = f"ID={ID} cat > '{job_dir}/{job_file['filename']}'"
            retval = exec_remote_command(headers, system_name, system_addr, action, file_transfer="upload", file_content=job_file['content'], no_home=use_plugin)
            if retval["error"] != 0:
                app.logger.error(f"(Error uploading file: {retval['msg']}")
                update_task(task_id, headers, async_task.ERROR, "Failed to upload file")
                return

        plugin_options = [SPANK_PLUGIN_OPTION] if use_plugin else None
        spec = Job(job_file['filename'], job_dir, account, plugin_options)
        scheduler_command = scheduler.submit(spec)
        ID = headers.get(TRACER_HEADER, '')
        action=f"ID={ID} {scheduler_command}"
        app.logger.info(action)

        retval = exec_remote_command(headers, system_name, system_addr, action, no_home=use_plugin)

        if retval["error"] != 0:
            app.logger.error(f"(Error: {retval['msg']}")
            update_task(task_id, headers, async_task.ERROR, retval["msg"])
            return

        outlines = retval["msg"]

        if outlines:
            app.logger.info(f"(No error) --> {outlines}")

        jobid = scheduler.extract_jobid(outlines)

        msg = {"result" : "Job submitted", "jobid" : jobid}

        # now look for log and err files location
        job_extra_info = get_job_files(headers, system_name, system_addr, msg,use_plugin=use_plugin)

        update_task(task_id, headers, async_task.SUCCESS, job_extra_info, True)

    except IOError as e:
        app.logger.error(e.filename, exc_info=True, stack_info=True)
        app.logger.error(e.strerror)
        update_task(task_id, headers,async_task.ERROR, e.message)
    except Exception as e:
        app.logger.error(type(e), exc_info=True, stack_info=True)
        app.logger.error(e)
        #traceback.print_exc(file=sys.stdout)
        update_task(task_id, headers, async_task.ERROR)

    return



# - headers: coming from OIDC + tracing
# - system_name, system_addr: machine where the command will be executed
# - job_info: json containing jobid key
# - output: True if StdErr and StdOut of the job need to be added to the jobinfo (default False)
def get_job_files(headers, system_name, system_addr, job_info, output=False, use_plugin=False):

    if debug:
        app.logger.info("Recovering data from job")

    # save msg, so we can add it later:
    control_info = job_info
    control_info["job_file_out"] = "Not available"
    control_info["job_file_err"] = "Not available"
    control_info["job_info_extra"] = "Job info returned successfully" # field for extra information about metadata of the job

    ID = headers.get(TRACER_HEADER, '')
    sched_command = scheduler.job_info(control_info['jobid'])
    action = f"ID={ID} {sched_command}"

    app.logger.info(f"job info command: {action}")

    n_tries = 2 #tries 2 times to get the information of the jobs, otherwise returns error msg

    for n_try in range(n_tries):

        resp = exec_remote_command(headers, system_name, system_addr, action, no_home=use_plugin)

        # if there was an error, the result will be SUCESS but not available outputs
        if resp["error"] == 0:
            break

        app.logger.warning(f"Error getting job info. Reason: {resp['msg']}")

        if n_try == n_tries - 1:
            app.logger.warning("Returning default values")
            control_info["job_info_extra"] = resp["msg"]
            return control_info

        time.sleep(TIMEOUT) # wait until next try

    control_dict = scheduler.parse_job_info(resp["msg"])

    control_info["job_file_out"] = control_dict.get("StdOut", "stdout-file-not-found")
    control_info["job_file_err"] = control_dict.get("StdErr", "stderr-file-not-found")
    control_info["job_file"] = control_dict.get("Command", "command-not-found")
    control_info["job_data_out"] = ""
    control_info["job_data_err"] = ""

    if output:
        # to add data from StdOut and StdErr files in Task
        # this is done when GET compute/jobs is triggered.
        #
        # tail -n {number_of_lines_since_end} or
        # tail -c {number_of_bytes} --> 1000B = 1KB

        action = f"ID={ID} timeout {TIMEOUT} tail -c {TAIL_BYTES} '{control_info['job_file_out']}'"
        resp = exec_remote_command(headers, system_name, system_addr, action, no_home=use_plugin)
        if resp["error"] == 0:
            control_info["job_data_out"] = resp["msg"]

        action = f"ID={ID} timeout {TIMEOUT} tail -c {TAIL_BYTES} '{control_info['job_file_err']}'"
        resp = exec_remote_command(headers, system_name, system_addr, action, no_home=use_plugin)
        if resp["error"] == 0:
            control_info["job_data_err"] = resp["msg"]

    return control_info

def submit_job_path_task(headers, system_name, system_addr, fileName, job_dir, account, use_plugin, task_id):

    plugin_options = [SPANK_PLUGIN_OPTION] if use_plugin else None
    spec = Job(fileName, job_dir, account, plugin_options)
    scheduler_command = scheduler.submit(spec)
    ID = headers.get(TRACER_HEADER, '')
    action=f"ID={ID} {scheduler_command}"
    app.logger.info(action)

    resp = exec_remote_command(headers, system_name, system_addr, action, no_home=use_plugin)

    # in case of error:
    if resp["error"] != 0:
        if resp["error"] == -2:
            update_task(task_id, headers, async_task.ERROR, "Machine is not available")
            return

        if resp["error"] == 1:
            err_msg = resp["msg"]
            if in_str(err_msg,"OPENSSH"):
                err_msg = "User does not have permissions to access machine"
            update_task(task_id, headers, async_task.ERROR, err_msg)
            return
        err_msg = resp["msg"]
        update_task(task_id, headers, async_task.ERROR, err_msg)

    jobid = scheduler.extract_jobid(resp["msg"])
    msg = {"result": "Job submitted", "jobid": jobid}

    # now looking for log and err files location
    job_extra_info = get_job_files(headers, system_name, system_addr, msg, use_plugin=use_plugin)

    update_task(task_id, headers, async_task.SUCCESS, job_extra_info, True)


## error handler for files above SIZE_LIMIT -> app.config['MAX_CONTENT_LENGTH']
@app.errorhandler(413)
def request_entity_too_large(error):
    app.logger.error(error)
    return jsonify(description=f"Failed to upload batch script. The file is over {MAX_FILE_SIZE} MB"), 413

# Submit a batch script to the workload manager on the target system.
# The batch script is uploaded as a file

@app.route("/jobs/upload",methods=["POST"])
@check_auth_header
def submit_job_upload():

    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header={"X-Machine-Does-Not-Exists":"Machine does not exists"}
        return jsonify(description="Failed to submit job file",error="Machine does not exists"), 400, header

    # check "account parameter"
    account = request.form.get("account", None)
    if account != None:
        v = validate_input(account)
        if v != "":
            return jsonify(description="Invalid account", error=f"'account' {v}"), 400

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    [headers, ID] = get_tracing_headers(request)
    # check if machine is accessible by user:
    resp = exec_remote_command(headers, system_name, system_addr, f"ID={ID} true")

    if resp["error"] != 0:
        error_str = resp["msg"]
        if resp["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(description="Failed to submit job file"), 400, header
        if in_str(error_str,"Permission") or in_str(error_str,"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Failed to submit job file"), 404, header

    job_base_fs = COMPUTE_BASE_FS[system_idx]

    try:
        # check if the post request has the file part
        if 'file' not in request.files:
            app.logger.error('No batch file part')
            error = jsonify(description="Failed to submit job file", error='No batch file part')
            return error, 400

        job_file = {'filename': secure_filename(request.files['file'].filename), 'content': request.files['file'].read()}

        # if user does not select file, browser also
        # submit an empty part without filename
        if job_file['filename'] == '':
            app.logger.error('No batch file selected')
            error = jsonify(description="Failed to submit job file", error='No batch file selected')
            return error, 400

    except RequestEntityTooLarge as re:
        app.logger.error(re.description)
        data = jsonify(description="Failed to submit job file", error=f"File is bigger than {MAX_FILE_SIZE} MB")
        return data, 413
    except Exception as e:
        data = jsonify(description="Failed to submit job file",error=e)
        return data, 400


    task_id = create_task(headers, service="compute")
    # if error in creating task:
    if task_id == -1:
        return jsonify(description="Failed to submit job file",error='Error creating task'), 400

    # create tmp file with timestamp
    # using hash_id from Tasks, which is user-task_id (internal)
    tmpdir = f"{task_id}"

    is_username_ok = get_username(headers[AUTH_HEADER_NAME])

    if not is_username_ok["result"]:
        return jsonify(description=is_username_ok["reason"],error='Error creating task'), 401

    username = is_username_ok["username"]

    job_dir = f"{job_base_fs}/{username}/firecrest/{tmpdir}"
    use_plugin  = USE_SPANK_PLUGIN[system_idx]

    app.logger.info(f"Job dir: {job_dir}")

    try:
        # asynchronous task creation
        aTask = threading.Thread(target=submit_job_task, name=ID,
                             args=(headers, system_name, system_addr, job_file, job_dir, account, use_plugin, task_id))

        aTask.start()
        retval = update_task(task_id, headers, async_task.QUEUED)

        task_url = f"{KONG_URL}/tasks/{task_id}"
        data = jsonify(success="Task created", task_id=task_id, task_url=task_url)
        return data, 201

    except Exception as e:
        data = jsonify(description="Failed to submit job",error=e)
        return data, 400

# Submit a batch script to scheduler on the target system.
# The batch script is into the target system
@app.route("/jobs/path",methods=["POST"])
@check_auth_header
def submit_job_path():

    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="Failed to submit job", error="No machine name given"), 400

    # public endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header={"X-Machine-Does-Not-Exists":"Machine does not exists"}
        return jsonify(description="Failed to submit job",error="Machine does not exists"), 400, header

    # iterate over SYSTEMS_PUBLIC list and find the endpoint matching same order

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]
    use_plugin = USE_SPANK_PLUGIN[system_idx]

    targetPath = request.form.get("targetPath", None)
    v = validate_input(targetPath)
    if v != "":
        return jsonify(description="Failed to submit job", error=f"'targetPath' {v}"), 400

    # check "account parameter"
    account = request.form.get("account", None)
    if account != None:
        v = validate_input(account)
        if v != "":
            return jsonify(description="Invalid account", error=f"'account' {v}"), 400

    [headers, ID] = get_tracing_headers(request)
    # check if machine is accessible by user:
    resp = exec_remote_command(headers, system_name, system_addr, f"ID={ID} true")

    if resp["error"] != 0:
        error_str = resp["msg"]
        if resp["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(description="Failed to submit job"), 400, header
        if in_str(error_str,"Permission") or in_str(error_str,"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Failed to submit job"), 404, header

    # checks if targetPath is a valid path for this user in this machine
    check = is_valid_file(targetPath, headers, system_name, system_addr)

    if not check["result"]:
        return jsonify(description="Failed to submit job"), 400, check["headers"]

    # creates the async task related to the job submission
    task_id = create_task(headers, service="compute")
    # if error in creating task:
    if task_id == -1:
        return jsonify(description="Failed to submit job",error='Error creating task'), 400

    job_dir = os.path.dirname(targetPath)

    try:
        # asynchronous task creation
        aTask = threading.Thread(target=submit_job_path_task, name=ID,
                             args=(headers, system_name, system_addr, targetPath, job_dir, account, use_plugin, task_id))

        aTask.start()
        update_task(task_id, headers, async_task.QUEUED, TASKS_URL)

        task_url = f"{KONG_URL}/tasks/{task_id}"
        data = jsonify(success="Task created", task_id=task_id, task_url=task_url)
        return data, 201

    except Exception as e:
        data = jsonify(description="Failed to submit job",error=e)
        return data, 400

# Retrieves information from the user's jobs
@app.route("/jobs",methods=["GET"])
@check_auth_header
def list_jobs():

    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Failed to retrieve jobs information", error="Machine does not exists"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    [headers, ID] = get_tracing_headers(request)
    # check if machine is accessible by user:
    resp = exec_remote_command(headers, system_name, system_addr, f"ID={ID} true")

    if resp["error"] != 0:
        error_str = resp["msg"]
        if resp["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(description="Failed to retrieve jobs information"), 400, header
        if in_str(error_str,"Permission") or in_str(error_str,"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Failed to retrieve jobs information"), 404, header

    is_username_ok = get_username(headers[AUTH_HEADER_NAME])

    if not is_username_ok["result"]:
        return jsonify(description=is_username_ok["reason"],error="Failed to retrieve jobs information"), 401

    username = is_username_ok["username"]

    app.logger.info(f"Getting information of jobs from {system_name} ({system_addr})")

    # job list comma separated:
    jobs        = request.args.get("jobs", None)
    pageSize    = request.args.get("pageSize", None)
    pageNumber  = request.args.get("pageNumber", None)

    if pageSize != None and pageNumber != None:
        try:
            pageNumber  = int(pageNumber)
            pageSize    = int(pageSize)

            if pageSize not in [10,25,50,100]:
                pageSize = 25

        except ValueError:
            pageNumber = 0
            pageSize = 25
            app.logger.error("Wrong pageNumber and/or pageSize")
    else:
        # if not set, by default
        pageNumber  = 0
        pageSize    = 25

    # by default empty
    job_aux_list = None
    if jobs != None:
        v = validate_input(jobs)
        if v != "":
            return jsonify(description="Failed to retrieve job information", error=f"'jobs' {v}"), 400
        try:
            # check if input is correct:
            job_aux_list = jobs.split(",")
            if '' in job_aux_list:
                return jsonify(error="Jobs list wrong format",description="Failed to retrieve job information"), 400

            for jobid in job_aux_list:
                if not scheduler.is_jobid(jobid):
                    return jsonify(error=f"{jobid} is not a valid job ID", description="Failed to retrieve job information"), 400

        except:
            return jsonify(error="Jobs list wrong format",description="Failed to retrieve job information"), 400

    action = f"ID={ID} {scheduler.poll(username, job_aux_list)}"

    try:
        task_id = create_task(headers, service="compute")

        # if error in creating task:
        if task_id == -1:
            return jsonify(description="Failed to retrieve job information",error='Error creating task'), 400

        update_task(task_id, headers, async_task.QUEUED)

        # asynchronous task creation
        aTask = threading.Thread(target=list_job_task, name=ID,
                                 args=(headers, system_name, system_addr, action, task_id, pageSize, pageNumber))

        aTask.start()

        task_url = f"{KONG_URL}/tasks/{task_id}"

        data = jsonify(success="Task created", task_id=task_id, task_url=task_url)
        return data, 200

    except Exception as e:
        data = jsonify(description="Failed to retrieve job information",error=e)
        return data, 400



def list_job_task(headers,system_name, system_addr,action,task_id,pageSize,pageNumber):
    # exec command
    resp = exec_remote_command(headers, system_name, system_addr, action)

    app.logger.info(resp)

    # in case of error:
    if resp["error"] == -2:
        update_task(task_id, headers, async_task.ERROR, "Machine is not available")
        return

    if resp["error"] == 1:
        err_msg = resp["msg"]
        if in_str(err_msg,"OPENSSH"):
            err_msg = "User does not have permissions to access machine"
        update_task(task_id, headers, async_task.ERROR, err_msg)
        return

    if len(resp["msg"]) == 0:
         update_task(task_id, headers, async_task.SUCCESS, {}, True)
         return


    # on success:
    jobList = scheduler.parse_poll_output(resp["msg"])
    app.logger.info(f"Size jobs: {len(jobList)}")

    # pagination
    totalSize   = len(jobList)
    pageNumber  = float(pageNumber)
    pageSize    = float(pageSize)

    totalPages = int(ceil(float(totalSize) / float(pageSize)))

    if debug:
        app.logger.info(f"Total Size: {totalSize} - Total Pages: {totalPages}")

    if pageNumber < 0 or pageNumber > totalPages-1:
        app.logger.warning(f"pageNumber ({pageNumber}) greater than total pages ({totalPages}), set to default = 0")
        pageNumber = 0

    beg_reg = int(pageNumber * pageSize)
    end_reg = int( (pageNumber+1 * pageSize) -1 )

    app.logger.info(f"Initial reg {beg_reg}, final reg: {end_reg}")

    jobList = jobList[beg_reg:end_reg + 1]

    jobs = {}
    for job_index, jobinfo in enumerate(jobList):
        # now looking for log and err files location
        jobinfo = get_job_files(headers, system_name, system_addr, jobinfo, True)

        # add jobinfo to the array
        jobs[str(job_index)]=jobinfo

    data = jobs

    update_task(task_id, headers, async_task.SUCCESS, data, True)



# Retrieves information from a jobid
@app.route("/jobs/<jobid>",methods=["GET"])
@check_auth_header
def list_job(jobid):

    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Failed to retrieve job information", error="Machine does not exists"), 400, header

    #check if jobid is a valid jobid for the scheduler
    if not scheduler.is_jobid(jobid):
        return jsonify(description="Failed to retrieve job information", error=f"{jobid} is not a valid job ID"), 400

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    [headers, ID] = get_tracing_headers(request)
    # check if machine is accessible by user:
    resp = exec_remote_command(headers, system_name, system_addr, f"ID={ID} true")

    if resp["error"] != 0:
        error_str = resp["msg"]
        if resp["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(description="Failed to retrieve job information"), 400, header
        if in_str(error_str,"Permission") or in_str(error_str,"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Failed to retrieve job information"), 404, header

    is_username_ok = get_username(headers[AUTH_HEADER_NAME])

    if not is_username_ok["result"]:
        return jsonify(description=is_username_ok["reason"],error="Failed to retrieve job information"), 401
    username = is_username_ok["username"]

    app.logger.info(f"Getting scheduler information of job={jobid} from {system_name} ({system_addr})")

    action = f"ID={ID} {scheduler.poll(username, [jobid])}"
    try:
        # obtain new task from Tasks microservice
        task_id = create_task(headers, service="compute")

        # if error in creating task:
        if task_id == -1:
            return jsonify(description="Failed to retrieve job information",error='Error creating task'), 400

        update_task(task_id, headers, async_task.QUEUED)

        # asynchronous task creation
        aTask = threading.Thread(target=list_job_task, name=ID,
                                 args=(headers, system_name, system_addr, action, task_id, 1, 1))

        aTask.start()

        task_url = f"{KONG_URL}/tasks/{task_id}"

        data = jsonify(success="Task created", task_id=task_id, task_url=task_url)
        return data, 200

    except Exception as e:
        data = jsonify(description="Failed to retrieve job information",error=e)
        return data, 400



def cancel_job_task(headers, system_name, system_addr, action, task_id):
    resp = exec_remote_command(headers, system_name, system_addr, action)

    app.logger.info(resp)

    data = resp["msg"]

    # in case of error:
    # permission denied, jobid to be canceled is owned by user without permission
    if resp["error"] == 210:
        update_task(task_id, headers, async_task.ERROR, "User does not have permission to cancel job")
        return

    if resp["error"] == -2:
        update_task(task_id, headers, async_task.ERROR, "Machine is not available")
        return

    if resp["error"] != 0:
        err_msg = resp["msg"]
        if in_str(err_msg,"OPENSSH"):
            err_msg = "User does not have permissions to access machine"
        update_task(task_id, headers, async_task.ERROR, err_msg)
        return

    # We may want to look for errors in the output, beyond the error code
    err_msg = scheduler.parse_cancel_output(data)
    if err_msg:
        update_task(task_id, headers, async_task.ERROR, err_msg)
        return

    # otherwise
    update_task(task_id, headers, async_task.SUCCESS, data)


# Cancel job
@app.route("/jobs/<jobid>",methods=["DELETE"])
@check_auth_header
def cancel_job(jobid):

    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Failed to delete job", error="Machine does not exists"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    v = validate_input(jobid)
    if v != "":
        return jsonify(description="Failed to delete job", error=f"'jobid' {v}"), 400

    [headers, ID] = get_tracing_headers(request)
    # check if machine is accessible by user:
    resp = exec_remote_command(headers, system_name, system_addr, f"ID={ID} true")

    if resp["error"] != 0:
        error_str = resp["msg"]
        if resp["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(description="Failed to delete job"), 400, header
        if in_str(error_str,"Permission") or in_str(error_str,"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Failed to delete job"), 404, header

    app.logger.info(f"Cancel scheduler job={jobid} from {system_name} ({system_addr})")
    action = f"ID={ID} {scheduler.cancel([jobid])}"
    try:
        # obtain new task from TASKS microservice.
        task_id = create_task(headers, service="compute")

        # if error in creating task:
        if task_id == -1:
            return jsonify(description="Failed to delete job",error='Error creating task'), 400

        # asynchronous task creation
        aTask = threading.Thread(target=cancel_job_task, name=ID,
                             args=(headers, system_name, system_addr, action, task_id))

        aTask.start()

        update_task(task_id, headers, async_task.QUEUED)

        task_url = f"{KONG_URL}/tasks/{task_id}"

        data = jsonify(success="Task created", task_id=task_id, task_url=task_url)
        return data, 200

    except Exception as e:
        data = jsonify(description="Failed to delete job",error=e)
        return data, 400


def acct_task(headers, system_name, system_addr, action, task_id):
    # exec remote command
    resp = exec_remote_command(headers, system_name, system_addr, action)

    app.logger.info(resp)

    # in case of error:
    if resp["error"] == -2:
        update_task(task_id, headers, async_task.ERROR, "Machine is not available")
        return

    # in case of error:
    if resp["error"] != 0:
        err_msg = resp["msg"]
        if in_str(err_msg,"OPENSSH"):
            err_msg = "User does not have permissions to access machine"
        update_task(task_id, headers, async_task.ERROR, err_msg)
        return

    if len(resp["msg"]) == 0:
        update_task(task_id, headers, async_task.SUCCESS, {}, True)
        return

    jobs = scheduler.parse_accounting_output(resp["msg"])

    # as it is a json data to be stored in Tasks, the is_json=True
    update_task(task_id, headers, async_task.SUCCESS, jobs, is_json=True)



# Job account information
@app.route("/acct",methods=["GET"])
@check_auth_header
def acct():
    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Failed to retrieve account information", error="Machine does not exists"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    [headers, ID] = get_tracing_headers(request)
    # check if machine is accessible by user:
    resp = exec_remote_command(headers, system_name, system_addr, f"ID={ID} true")

    if resp["error"] != 0:
        error_str = resp["msg"]
        if resp["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(description="Failed to retrieve account information"), 400, header
        if in_str(error_str,"Permission") or in_str(error_str,"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Failed to retrieve account information"), 404, header

    starttime = request.args.get("starttime","")
    endtime   = request.args.get("endtime","")
    # check optional parameter jobs=jobidA,jobidB,jobidC
    jobs = request.args.get("jobs", "")
    if jobs != "":
        v = validate_input(jobs)
        if v != "":
            return jsonify(description="Failed to retrieve account information", error=f"'jobs' {v}"), 400

    sched_cmd = scheduler.accounting(
        jobids=jobs.split(','),
        start_time=starttime,
        end_time=endtime
    )
    action = f"ID={ID} {sched_cmd}"

    try:
        # obtain new task from Tasks microservice
        task_id = create_task(headers, service="compute")

        # if error in creating task:
        if task_id == -1:
            return jsonify(description="Failed to retrieve account information",error='Error creating task'), 400

        update_task(task_id, headers, async_task.QUEUED)

        # asynchronous task creation
        aTask = threading.Thread(target=acct_task, name=ID,
                                 args=(headers, system_name, system_addr, action, task_id))

        aTask.start()
        task_url = f"{KONG_URL}/tasks/{task_id}"

        data = jsonify(success="Task created", task_id=task_id, task_url=task_url)
        return data, 200

    except Exception as e:
        data = jsonify(description="Failed to retrieve account information",error=e)
        return data, 400

@app.route("/status",methods=["GET"])
@check_auth_header
def status():
    app.logger.info("Test status of service")
    # TODO: check compute reservation binary to truthfully respond this request
    return jsonify(success="ack"), 200

@app.before_request
def f_before_request():
    new_headers = {}
    if JAEGER_AGENT != "":
        try:
            jaeger_tracer.inject(tracing.get_span(request), opentracing.Format.TEXT_MAP, new_headers)
        except Exception as e:
            logging.error(e)
    g.TID = new_headers.get(TRACER_HEADER, '')

@app.after_request
def after_request(response):
    # LogRequestFormatetter is used, this messages will get time, thread, etc
    logger.info('%s %s %s %s %s', request.remote_addr, request.method, request.scheme, request.full_path, response.status)
    return response


if __name__ == "__main__":
    if USE_SSL:
        app.run(debug=debug, host='0.0.0.0', port=COMPUTE_PORT, ssl_context=(SSL_CRT, SSL_KEY))
    else:
        app.run(debug=debug, host='0.0.0.0', port=COMPUTE_PORT)
