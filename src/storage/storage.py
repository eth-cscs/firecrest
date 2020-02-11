#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from flask import Flask, request, jsonify

import keystone
import json, tempfile, os

import async_task
import threading
# logging handler
from logging.handlers import TimedRotatingFileHandler
# common functions
from cscs_api_common import check_header, get_username
from cscs_api_common import create_task, update_task, get_task_status
from cscs_api_common import exec_remote_command

# job_time_checker for correct SLURM job time in /xfer-internal tasks
import job_time

# for debug purposes
import logging

import requests
from hashlib import md5

## READING vars environment vars

CERTIFICATOR_URL = os.environ.get("CERTIFICATOR_URL")
TASKS_URL        = os.environ.get("TASKS_URL")
COMPUTE_URL      = os.environ.get("COMPUTE_URL")
STATUS_IP        = os.environ.get("STATUS_IP")
KONG_URL         = os.environ.get("KONG_URL")

STORAGE_PORT     = os.environ.get("STORAGE_PORT", 5000)

AUTH_HEADER_NAME = 'Authorization'

# Machines for Storage:
# Filesystem DNS or IP where to download or upload files:
SYSTEMS_INTERNAL_STORAGE = os.environ.get("SYSTEMS_INTERNAL_STORAGE").strip('\'"')
# Job machine where to send xfer-internal jobs (must be defined in SYSTEMS_PUBLIC)
STORAGE_JOBS_MACHINE     = os.environ.get("STORAGE_JOBS_MACHINE").strip('\'"')

###### ENV VAR FOR DETECT TECHNOLOGY OF STAGING AREA:
OBJECT_STORAGE = os.environ.get("OBJECT_STORAGE", "").strip('\'"')

# Scheduller partition used for internal transfers
XFER_PARTITION = os.environ.get("XFER_PARTITION", "").strip('\'"')

# Machine used for external transfers

EXT_TRANSFER_MACHINE_PUBLIC=os.environ.get("EXT_TRANSFER_MACHINE_PUBLIC", "").strip('\'"')
EXT_TRANSFER_MACHINE_INTERNAL=os.environ.get("EXT_TRANSFER_MACHINE_INTERNAL", "").strip('\'"')

OS_AUTH_URL             = os.environ.get("OS_AUTH_URL")
OS_IDENTITY_PROVIDER    = os.environ.get("OS_IDENTITY_PROVIDER")
OS_IDENTITY_PROVIDER_URL= os.environ.get("OS_IDENTITY_PROVIDER_URL")
OS_PROTOCOL             = os.environ.get("OS_PROTOCOL")
OS_INTERFACE            = os.environ.get("OS_INTERFACE")
OS_PROJECT_ID           = os.environ.get("OS_PROJECT_ID")

# SECRET KEY for temp url without using Token
SECRET_KEY              = os.environ.get("SECRET_KEY")

STORAGE_TEMPURL_EXP_TIME = int(os.environ.get("STORAGE_TEMPURL_EXP_TIME", "2592000").strip('\'"'))
STORAGE_MAX_FILE_SIZE = int(os.environ.get("STORAGE_MAX_FILE_SIZE", "5368709120").strip('\'"'))


# aynchronous tasks: upload & download --> http://TASKS_URL
# {task_id : AsyncTask}

storage_tasks = {}

# relationship between upload task and filesystem
# {hash_id : {'user':user,'system':system,'target':path,'source':fileName,'hash_id':task_id}}
uploaded_files = {}

# debug on console
debug = os.environ.get("DEBUG_MODE", None)


app = Flask(__name__)



# async task for download large files
# user: user in the posix file system
# system: system in which the file will be stored (REMOVE later)
# sourcePath: path in FS where the object is
# task_id: async task id given for Tasks microservice

def download_task(auth_header,system,sourcePath,task_id):
    object_name = sourcePath.split("/")[-1]
    global staging

    # check if staging area token is valid
    if not staging.is_token_valid():
        if not staging.authenticate():
            msg = "Staging area auth error"
            update_task(task_id, auth_header, async_task.ERROR, msg)
            return

    # create container if it doesn't exists:
    container_name = get_username(auth_header)

    if not staging.is_container_created(container_name):
        errno = staging.create_container(container_name)

        if errno == -1:
            msg="Could not create container {container_name} in Staging Area ({staging_name})".format(container_name=container_name, staging_name=staging.get_object_storage())
            update_task(task_id, auth_header, async_task.ERROR, msg)
            return

    # upload file to swift
    object_prefix = task_id

    upload_url = staging.create_upload_form(sourcePath, container_name, object_prefix, STORAGE_TEMPURL_EXP_TIME, STORAGE_MAX_FILE_SIZE)

    # advice Tasks that upload begins:
    update_task(task_id, auth_header, async_task.ST_UPL_BEG)

    # upload starts:
    res = exec_remote_command(auth_header,system,upload_url["command"])

    # if upload to SWIFT fails:
    if res["error"] == 1:
        msg = "Upload to Staging area has failed. Object: {object_name}".format(object_name=object_name)
        app.logger.error(msg)
        update_task(task_id, auth_header, async_task.ST_UPL_ERR, msg)
        return


    # get Download Temp URL with [seconds] time expiration
    # create temp url for file: valid for STORAGE_TEMPURL_EXP_TIME seconds
    temp_url = staging.create_temp_url(container_name, object_prefix, object_name, STORAGE_TEMPURL_EXP_TIME)

    # if error raises in temp url creation:
    if temp_url == None:
        msg = "Temp URL creation failed. Object: {object_name}".format(object_name=object_name)
        update_task(task_id, auth_header, async_task.ERROR, msg)
        return

    # if succesfully created: temp_url in task with success status
    update_task(task_id, auth_header,async_task.ST_UPL_END, temp_url)
    retval = staging.delete_object_after(containername=container_name,prefix=object_prefix,objectname=object_name,ttl=STORAGE_TEMPURL_EXP_TIME)

    if retval == 0:
        app.logger.info("Setting {seconds} [s] as X-Delete-After".format(seconds=STORAGE_TEMPURL_EXP_TIME))
    else:
        app.logger.error("Object couldn't be marked as X-Delete-After")



# download large file, returns temp url for downloading
@app.route("/xfer-external/download", methods=["POST"])
def download_request():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    # TODO: change for dom; the first IP is for daint, the second for dom.
    system = SYSTEMS_INTERNAL_STORAGE.split(";")[0]
    sourcePath = request.form["sourcePath"]  # path file in cluster

    if sourcePath == None:
        data = jsonify(error="Source path not set in request")
        return data, 400

    # obtain new task from Tasks microservice
    task_id = create_task(auth_header, service="storage")

    # couldn't create task
    if task_id == -1:
        data = jsonify(error="Coludn't create task")
        return data, 400

    # asynchronous task creation
    aTask = threading.Thread(target=download_task,
                             args=(auth_header, system, sourcePath, task_id))

    storage_tasks[task_id] = aTask

    try:
        update_task(task_id, auth_header, async_task.QUEUED)

        storage_tasks[task_id].start()

        task_url = "{kong_url}/tasks/{task_id}".format(kong_url=KONG_URL, task_id=task_id)

        data = jsonify(success="Task created", task_url=task_url, task_id=task_id)
        return data, 200

    except Exception as e:
        data = jsonify(error=e)
        return data, 400


# async task for upload large files
# user: user in the posix file system
# system: system in which the file will be stored (REMOVE later)
# targetPath: absolute path in which to store the file
# sourcePath: absolute path in local FS
# task_id: async task_id created with Tasks microservice
def upload_task(auth_header,system,targetPath,sourcePath,task_id):

    fileName = sourcePath.split("/")[-1]

    # container to bind:
    container_name = get_username(auth_header)

    # change hash_id for task_id since is not longer needed for (failed) redirection
    uploaded_files[task_id] = {"user": container_name,
                               "system": system,
                               "target": targetPath,
                               "source": fileName,
                               "hash_id": task_id}

    data = uploaded_files[task_id]

    global staging
    data["msg"] = "Waiting for Presigned URL to upload file to staging area ({})".format(staging.get_object_storage())

    # change to dictionary containing upload data (for backup purpouses) and adding url call
    update_task(task_id, auth_header, async_task.ST_URL_ASK, data, is_json=True)

    # check if staging token is valid
    if not staging.is_token_valid():
        if not staging.authenticate():
            data = uploaded_files[task_id]
            msg = "Staging Area auth error, try again later"
            data["msg"] = msg
            update_task(task_id, auth_header, async_task.ERROR, data, is_json=True)
            return


    # create or return container
    if not staging.is_container_created(container_name):
        errno = staging.create_container(container_name)

        if errno == -1:
            data = uploaded_files[task_id]
            msg="Could not create container {container_name} in Staging Area ({staging_name})".format(container_name=container_name, staging_name=staging.get_object_storage())
            data["msg"] = msg
            update_task(task_id,auth_header, async_task.ERROR,data,is_json=True)
            return

    object_prefix = task_id

    # create temporary upload form
    resp = staging.create_upload_form(sourcePath, container_name, object_prefix, STORAGE_TEMPURL_EXP_TIME, STORAGE_MAX_FILE_SIZE)
    data = uploaded_files[task_id]

    data["msg"] = resp

    update_task(task_id,auth_header,async_task.ST_URL_REC,data,is_json=True)

    return


# upload API entry point:
@app.route("/xfer-external/upload",methods=["POST","PUT"])
def upload_request():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    # if method used is PUT, then is to modify the upload process
    # add task_id header for upload_finished
    if request.method == "PUT":
        try:
            task_id = request.headers["X-Task-ID"]
            app.logger.info("Upload finished request with task_id: {task_id}".format(task_id=task_id))

            retval = upload_finished_call(hash_id=task_id, auth_header=auth_header)

            data = retval["data"]
            code = retval["code"]

            if code != 200:
                return jsonify(error=data), code

            return jsonify(success=data), code

        except KeyError as e:
            app.logger.info("Not a upload finished request")


    # TODO: change for dom; the first IP is for daint, the second for dom.
    # system       = SYSTEMS_INTERNAL_STORAGE.split(";")[0]

    app.logger.info(EXT_TRANSFER_MACHINE_INTERNAL)
    system = EXT_TRANSFER_MACHINE_INTERNAL



    targetPath   = request.form["targetPath"] # path to save file in cluster
    sourcePath   = request.form["sourcePath"] # path from the local FS


    if system == None:
        data = jsonify(error="System not set in request")
        return data, 400

    if targetPath == None:
        data = jsonify(error="Target path not set in request")
        return data, 400

    if sourcePath == None:
        data = jsonify(error="Source path not set in request")
        return data, 400


    # obtain new task from Tasks microservice
    task_id = create_task(auth_header,service="storage")

    if task_id == -1:
        return jsonify(error="Error creating task"), 400

    # asynchronous task creation
    try:
        update_task(task_id, auth_header, async_task.QUEUED)

        aTask = threading.Thread(target=upload_task,
                             args=(auth_header,system,targetPath,sourcePath,task_id))

        storage_tasks[task_id] = aTask

        storage_tasks[task_id].start()

        task_url = "{kong_url}/tasks/{task_id}".format(kong_url=KONG_URL,task_id=task_id)

        data = jsonify(success="Task created",task_url=task_url,task_id=task_id)
        return data, 200

    except Exception as e:
        data = jsonify(error=e.message)
        return data, 400



# use wget to download file from download_url created with swift
def get_file_from_storage(auth_header,system,path,download_url,fileName):

    app.logger.info("Trying downloading {url} from Object Storage to {system}".
                    format(url=download_url,system=system))

    # wget to be executed on cluster side:
    action = "wget -q -O {directory}/{fileName} \"{url}\" ".\
        format(directory=path,url=download_url,fileName=fileName)

    app.logger.info("{action}".format(action=action))

    retval = exec_remote_command(auth_header,system,action)

    return retval



## upload callback asynchronous task: has_id and task_id
def upload_finished_task(auth_header, system, targetPath, sourcePath, hash_id):

    global staging

    if not staging.is_token_valid():
        if not staging.authenticate():
            msg = "Staging area auth error"
            update_task(hash_id, auth_header, async_task.ERROR, msg)
            return


    # get username from auth_header
    username = get_username(auth_header)

    if not staging.is_object_created(containername=username,prefix=hash_id,objectname=sourcePath):
        data = uploaded_files[hash_id]
        msg = "File {object} not found in Staging area".format(object=sourcePath)
        data["msg"] = msg
        # update_task(hash_id,auth_header,async_task.ERROR,data,is_json=True)
        return

    # register that is starting to get download temp url
    data = uploaded_files[hash_id]
    # update_task(hash_id,auth_header, async_task.ST_TMP_ASK, data, is_json=True)

    # temp_url = get_temp_url(sourcePath,hash_id,username,STORAGE_TEMPURL_EXP_TIME)
    temp_url = staging.create_temp_url(containername=username,prefix=hash_id,objectname=sourcePath,ttl=STORAGE_TEMPURL_EXP_TIME)

    if temp_url==None:
        msg = "Error in download temp URL creation, try again later"
        data["msg"] = msg
        update_task(hash_id, auth_header, async_task.ST_DWN_ERR,data,is_json=True)
        return

    app.logger.info("[TASK_ID: {task_id}] Temp URL: {tempUrl}".format(task_id=hash_id,tempUrl=temp_url))
    data = uploaded_files[hash_id]

    # register download to server started
    update_task(hash_id,auth_header, async_task.ST_DWN_BEG, data, is_json=True)
    res = get_file_from_storage(auth_header,system,targetPath,temp_url,sourcePath) #download file to system

    # result {"error": "error_msg"}
    if res["error"] != 0:
        app.logger.error("Error in download from Staging area to Server")
        app.logger.error(res["error"])
        app.logger.error(res["msg"])
        msg = res["msg"]
        data["msg"] = msg
        update_task(hash_id,auth_header,async_task.ST_DWN_ERR, data, is_json=True)
        #return jsonify(error=res["msg"])

    else:
        # update task with success signal
        update_task(hash_id, auth_header,async_task.ST_DWN_END,data,is_json=True)

        # delete upload request
        del uploaded_files[hash_id]

        # delete temp object from SWIFT
        # delete_object(username,sourcePath,hash_id)
        staging.delete_object(containername=username,prefix=hash_id,objectname=sourcePath)


# de-couple the upload finished task so it can be used in 2 ways:
# - xfer-external/upload-finished/<hash_id>
# - xfer-external/upload -H "TASKID:<hash_id>"

def upload_finished_call(hash_id,auth_header):
    # register change in status, after user ask for upload finished
    # and check if task exists
    try:
        data = uploaded_files[hash_id]

        task_status = get_task_status(hash_id, auth_header)

        # if task isn't found in Tasks:
        if task_status == -1:
            return {"data":"Couldn't find task {hash_id} status".format(hash_id=hash_id) , "code":404}

    except KeyError as e:
        return {"data":"Not found Hash_ID: {hash_id}".format(hash_id=hash_id), "code": 404}

    # check staging area token validation

    global staging

    if not staging.is_token_valid():
        if not staging.authenticate():
            data = uploaded_files[hash_id]
            data["msg"] = "OpenStack Keystone auth error, try again later"

            return {"data":data["resp"], "code":400}

    try:
        # [user,system,targetPath,sourcePath,task_id] = uploaded_files[hash_id]
        # data = uploaded_files[hash_id]
        user = data["user"]
        sourcePath = data["source"]
        system = data["system"]
        target = data["target"]

        app.logger.info("Source: {}".format(sourcePath))
        app.logger.info("Target: {}".format(target))

        # if object is not in OS, then that's an error,
        # and it means that upload wasn't finished jet

        if not staging.is_object_created(containername=user,prefix=hash_id,objectname=sourcePath):
            return {"data" : "Object isn't in SWIFT Object Storage", "code":400}

        # unless last upload_finished hasn't finished with error or never uploaded,
        # then the file is being or was uploaded
        if not (task_status == async_task.ST_DWN_ERR or task_status == async_task.ST_URL_REC):
            return { "data":"'upload_finished' request has been already made", "code":400}

        # register change in status, after upload finished confirmed by SWIFT
        # data = uploaded_files[hash_id]

        update_task(hash_id, auth_header, async_task.ST_UPL_CFM, data, is_json=True)

        # if object is in OS, then starts to download to cluster:
        staging.delete_object_after(containername=user, prefix=hash_id, objectname=sourcePath, ttl=STORAGE_TEMPURL_EXP_TIME)

    except KeyError:
        # if hash_id not exists:
        return {"data":"Task has not a valid format" , "code":400}

    try:
        # asynchronous task creation

        data = uploaded_files[hash_id]
        data["msg"] = "Starting async task for download to filesystem"

        # update_task(hash_id, auth_header, async_task.PROGRESS,"Starting download to File System")
        update_task(hash_id, auth_header, async_task.ST_DWN_BEG, data, is_json=True)

        aTask = threading.Thread(target=upload_finished_task,
                                 args=(auth_header,system,target,sourcePath,hash_id,))

        # replace the old upload_task using the same task_id
        storage_tasks[hash_id] = aTask
        storage_tasks[hash_id].start()

        return {"data":"Starting download to File System", "code": 200}

    except Exception as e:
        return {"data":e.message, "code":404}


## Internal Transfer MicroServices:
## cp / rm / mv / rsync using Jobs microservice


# executes system cp/mv/rm or rsync (xfer-internal)
# creates a sbatch file to execute in --partition=xfer
# user_header for user identification
# command = "cp" "mv" "rm" "rsync"
# sourcePath = source object path
# targetPath = in "rm" command should be ""
# jobName = --job-name parameter to be used on sbatch command
# jobTime = --time  parameter to be used on sbatch command
# stageOutJobId = value to set in --dependency:afterok parameter
def exec_internal_command(auth_header,command,sourcePath, targetPath, jobName, jobTime, stageOutJobId):


    action = "{command} {sourcePath} {targetPath}".\
                format(command=command, sourcePath=sourcePath, targetPath=targetPath)
    try:
        td = tempfile.mkdtemp(prefix="job")

        sbatch_file = open(td + "/sbatch-job.sh", "w")

        sbatch_file.write("#! /bin/bash\n")
        sbatch_file.write("#SBATCH --job-name={jobName}\n".format(jobName=jobName))
        sbatch_file.write("#SBATCH --time={jobTime}\n".format(jobTime=jobTime))
        sbatch_file.write("#SBATCH --error=job-%j.err\n")
        sbatch_file.write("#SBATCH --output=job-%j.out\n")
        sbatch_file.write("#SBATCH --ntasks=1\n")
        sbatch_file.write("#SBATCH --partition={xfer}\n".format(xfer=XFER_PARTITION))
        # test line for error
        # sbatch_file.write("#SBATCH --constraint=X2450\n")

        if stageOutJobId != None:
            sbatch_file.write("#SBATCH --dependency=afterok:{stageOutJobId}\n".format(stageOutJobId=stageOutJobId))

        sbatch_file.write("\n")
        sbatch_file.write("echo -e \"$SLURM_JOB_NAME started on $(date): {action}\"\n".format(action=action))
        sbatch_file.write("srun -n $SLURM_NTASKS {action}\n".format(action=action))
        sbatch_file.write("echo -e \"$SLURM_JOB_NAME finished on $(date)\"\n")

        sbatch_file.close()

    except IOError as ioe:
        app.logger.error(ioe.message)
        result = {"error": 1, "msg":ioe.message}
        return result

    # create xfer job
    resp = create_xfer_job(STORAGE_JOBS_MACHINE, auth_header, td + "/sbatch-job.sh")

    # remove sbatch file and dir
    os.remove(td + "/sbatch-job.sh")
    os.rmdir(td)

    return resp


# Internal cp transfer via SLURM with xfer partition:
@app.route("/xfer-internal/cp", methods=["POST"])
def internal_cp():
    return internal_operation(request, "cp")

# Internal mv transfer via SLURM with xfer partition:
@app.route("/xfer-internal/mv", methods=["POST"])
def internal_mv():
    return internal_operation(request, "mv")


# Internal rsync transfer via SLURM with xfer partition:
@app.route("/xfer-internal/rsync", methods=["POST"])
def internal_rsync():
    return internal_operation(request, "rsync")


# Internal rm transfer via SLURM with xfer partition:
@app.route("/xfer-internal/rm", methods=["POST"])
def internal_rm():
    return internal_operation(request, "rm")


# common code for internal cp, mv, rsync, rm
def internal_operation(request, command):
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        targetPath = request.form["targetPath"]  # path to save file in cluster
    except:
        app.logger.error("targetPath not specified")
        return jsonify(error="targetPath not specified"), 400

    if command in ['cp', 'mv', 'rsync']:
        try:
            sourcePath = request.form["sourcePath"]  # path to get file in cluster
        except:
            app.logger.error("sourcePath not specified")
            return jsonify(error="sourcePath not specified"), 400
    else:
        # for 'rm' there's no source, set empty to call exec_internal_command(...)
        sourcePath = ""

    try:
        jobName = request.form["jobName"]  # jobName for SLURM
        if jobName == None or jobName == "":
            jobName = command + "-job"
            app.logger.info("jobName not found, setting default to: {jobName}".format(jobName=jobName))
    except:
        jobName = command + "-job"
        app.logger.info("jobName not found, setting default to: {jobName}".format(jobName=jobName))

    try:
        jobTime = request.form["time"]  # job time, default is 2:00:00 H:M:s
        if not job_time.check_jobTime(jobTime):
            return jsonify(error="Not supported time format"), 400
    except:
        jobTime = "02:00:00"

    try:
        stageOutJobId = request.form["stageOutJobId"]  # start after this JobId has finished
    except:
        stageOutJobId = None

    retval = exec_internal_command(auth_header, command, sourcePath, targetPath, jobName, jobTime, stageOutJobId)

    # returns "error" key or "success" key
    try:
        error = retval["error"]
        errmsg = retval["msg"]
        desc = retval["desc"]
        # headers values cannot contain "\n" strings
        return jsonify(error=desc), 400, {"X-Sbatch-Error": errmsg}
    except KeyError:
        success = retval["success"]
        task_id = retval["task_id"]
        return jsonify(success=success, task_id=task_id), 201


# function to call SBATCH in --partition=xfer
# uses Jobs microservice API call: POST http://{compute_url}/{machine}
# all calls to cp, mv, rm or rsync are made using Jobs us.
def create_xfer_job(machine,auth_header,fileName):

    files = {'file': open(fileName, 'rb')}

    try:
        req = requests.post("{compute_url}/jobs".
                            format(compute_url=COMPUTE_URL),
                            files=files, headers={AUTH_HEADER_NAME: auth_header, "X-Machine-Name":machine})

        retval = json.loads(req.text)
        if not req.ok:
            return {"error":1,"msg":retval["description"],"desc":retval["error"]}

        return retval

    except Exception as e:
        app.logger.error(e)
        return {"error":1,"msg":e}



# get status for status microservice
# only used by STATUS_IP otherwise forbidden

@app.route("/status",methods=["GET"])
def status():

    app.logger.info("Test status of service")

    if request.remote_addr != STATUS_IP:
        app.logger.warning("Invalid remote address: {addr}".format(addr=request.remote_addr))
        return jsonify(error="Invalid access"), 403

    return jsonify(success="ack"), 200


def create_staging():
    # Object Storage object
    global staging

    staging = None

    if OBJECT_STORAGE == "swift":

        app.logger.info("Into swift")

        from swiftOS import Swift

        # Object Storage URL & data:
        SWIFT_URL = os.environ.get("SWIFT_URL")
        SWIFT_API_VERSION = os.environ.get("SWIFT_API_VERSION")
        SWIFT_ACCOUNT = os.environ.get("SWIFT_ACCOUNT")
        SWIFT_USER = os.environ.get("SWIFT_USER")
        SWIFT_PASS = os.environ.get("SWIFT_PASS")

        url = "{swift_url}/{swift_api_version}/AUTH_{swift_account}".format(
            swift_url=SWIFT_URL, swift_api_version=SWIFT_API_VERSION, swift_account=SWIFT_ACCOUNT)

        staging = Swift(url=url, user=SWIFT_USER, passwd=SWIFT_PASS, secret=SECRET_KEY)

    elif OBJECT_STORAGE == "s3":
        app.logger.info("Into s3")
        from s3OS import S3

        # For S#:
        S3_URL = os.environ.get("S3_URL")
        S3_ACCESS_KEY = os.environ.get("S3_ACCESS_KEY")
        S3_SECRET_KEY = os.environ.get("S3_SECRET_KEY")

        staging = S3(url=S3_URL, user=S3_ACCESS_KEY, passwd=S3_SECRET_KEY)

    else:
        app.logger.warning("No Object Storage for staging area was set.")


def init_storage():
    # should check Tasks tasks than belongs to storage

    create_staging()

    try:
        app.logger.info("Staging Area Used: {}".format(staging.url))
        app.logger.info("ObjectStorage Technology: {}".format(staging.get_object_storage()))

        # query Tasks microservice for previous tasks. Allow 30 seconds to answer
        retval=requests.get("{tasks_url}/taskslist".format(tasks_url=TASKS_URL), timeout=30)

        if retval.status_code != 200:
            app.logger.error("Error getting tasks from Tasks microservice")
            return False

        queue_tasks = retval.json()

        # queue_tasks structure: "tasks"{
        #                                  task_{id1}: {..., data={} }
        #                                  task_{id2}: {..., data={} }  }
        # data is the field containing every

        queue_tasks = queue_tasks["tasks"]

        n_tasks = 0

        for key,task in queue_tasks.items():
            app.logger.info(key)
            task = json.loads(task)

            # iterating over queue_tasls
            try:
                data = task["data"]

                # check if task is a non ending /xfer-external/upload downloading
                # from SWIFT to filesystem and it crashed before download finished,
                # so it can be re-initiated with /xfer-external/upload-finished
                # In that way it's is marked as erroneous

                if task["status"] == async_task.ST_DWN_BEG:
                    task["status"] = async_task.ST_DWN_ERR
                    task["description"] = "Storage has been restarted, restart upload-finished"

                    update_task(task["hash_id"], "", async_task.ST_DWN_ERR, data, is_json=True)

                uploaded_files[task["hash_id"]] = data

                n_tasks += 1

            except KeyError as e:
                app.logger.error(e)
                app.logger.error(task["data"])
                app.logger.error(key)

            except Exception as e:
                # app.logger.error("hash_id={hash_id}".format(hash_id=data["hash_id"]))
                app.logger.error(data)
                app.logger.error(e)
                app.logger.error(type(e))

        app.logger.info("Tasks saved: {n}".format(n=n_tasks))


    except Exception as e:
        app.logger.warning("TASKS microservice is down")
        app.logger.warning("STORAGE microservice will not be fully functional")
        app.logger.error(e)


if __name__ == "__main__":
    # log handler definition
    # timed rotation: 1 (interval) rotation per day (when="D")
    logHandler = TimedRotatingFileHandler('/var/log/storage.log', when='D', interval=1)

    logFormatter = logging.Formatter('%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                                     '%Y-%m-%d:%H:%M:%S')
    logHandler.setFormatter(logFormatter)
    logHandler.setLevel(logging.DEBUG)

    # get app log (Flask+werkzeug+python)
    logger = logging.getLogger()

    # set handler to logger
    logger.addHandler(logHandler)

    # checks QueuePersistence and retakes all tasks
    init_storage()

    app.run(debug=debug, host='0.0.0.0', use_reloader=False, port=STORAGE_PORT)
