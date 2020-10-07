#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from flask import Flask, request, jsonify

import keystone
import json, tempfile, os
import urllib
import datetime

import async_task
import threading
# logging handler
from logging.handlers import TimedRotatingFileHandler
# common functions
from cscs_api_common import check_auth_header, get_username
from cscs_api_common import create_task, update_task, get_task_status
from cscs_api_common import exec_remote_command
from cscs_api_common import create_certificate
from cscs_api_common import in_str
from cscs_api_common import is_valid_file, is_valid_dir

# job_time_checker for correct SLURM job time in /xfer-internal tasks
import job_time

# for debug purposes
import logging

import requests
from hashlib import md5

import stat
from cryptography.fernet import Fernet
import time

## READING vars environment vars

CERTIFICATOR_URL = os.environ.get("F7T_CERTIFICATOR_URL")
TASKS_URL        = os.environ.get("F7T_TASKS_URL")
COMPUTE_URL      = os.environ.get("F7T_COMPUTE_URL")
STATUS_IP        = os.environ.get("F7T_STATUS_IP")
KONG_URL         = os.environ.get("F7T_KONG_URL")

STORAGE_PORT     = os.environ.get("F7T_STORAGE_PORT", 5000)

AUTH_HEADER_NAME = 'Authorization'

# Machines for Storage:
# Filesystem DNS or IP where to download or upload files:
SYSTEMS_INTERNAL_STORAGE = os.environ.get("F7T_SYSTEMS_INTERNAL_STORAGE").strip('\'"')
# Job machine where to send xfer-internal jobs (must be defined in SYSTEMS_PUBLIC)
STORAGE_JOBS_MACHINE     = os.environ.get("F7T_STORAGE_JOBS_MACHINE").strip('\'"')

# SYSTEMS_PUBLIC: list of allowed systems
# remove quotes and split into array
SYSTEMS_PUBLIC  = os.environ.get("F7T_SYSTEMS_PUBLIC").strip('\'"').split(";")
# internal machines to submit/query jobs
SYS_INTERNALS   = os.environ.get("F7T_SYSTEMS_INTERNAL_COMPUTE").strip('\'"').split(";")

###### ENV VAR FOR DETECT TECHNOLOGY OF STAGING AREA:
OBJECT_STORAGE = os.environ.get("F7T_OBJECT_STORAGE", "").strip('\'"')

# Scheduller partition used for internal transfers
XFER_PARTITION = os.environ.get("F7T_XFER_PARTITION", "").strip('\'"')

# Machine used for external transfers

EXT_TRANSFER_MACHINE_PUBLIC=os.environ.get("F7T_EXT_TRANSFER_MACHINE_PUBLIC", "").strip('\'"')
EXT_TRANSFER_MACHINE_INTERNAL=os.environ.get("F7T_EXT_TRANSFER_MACHINE_INTERNAL", "").strip('\'"')

OS_AUTH_URL             = os.environ.get("F7T_OS_AUTH_URL")
OS_IDENTITY_PROVIDER    = os.environ.get("F7T_OS_IDENTITY_PROVIDER")
OS_IDENTITY_PROVIDER_URL= os.environ.get("F7T_OS_IDENTITY_PROVIDER_URL")
OS_PROTOCOL             = os.environ.get("F7T_OS_PROTOCOL")
OS_INTERFACE            = os.environ.get("F7T_OS_INTERFACE")
OS_PROJECT_ID           = os.environ.get("F7T_OS_PROJECT_ID")

# SECRET KEY for temp url without using Token
SECRET_KEY              = os.environ.get("F7T_SECRET_KEY")

# Expiration time for temp URLs in seconds, by default 30 days
STORAGE_TEMPURL_EXP_TIME = int(os.environ.get("F7T_STORAGE_TEMPURL_EXP_TIME", "2592000").strip('\'"'))
# max file size for temp URLs in MegaBytes, by default 5120 MB = 5 GB
STORAGE_MAX_FILE_SIZE = int(os.environ.get("F7T_STORAGE_MAX_FILE_SIZE", "5120").strip('\'"'))
# for use on signature of URL it must be in bytes (MB*1024*1024 = Bytes)
STORAGE_MAX_FILE_SIZE *= 1024*1024

STORAGE_POLLING_INTERVAL = int(os.environ.get("F7T_STORAGE_POLLING_INTERVAL", "60").strip('\'"'))
CERT_CIPHER_KEY = os.environ.get("F7T_CERT_CIPHER_KEY", "").strip('\'"').encode('utf-8')


# aynchronous tasks: upload & download --> http://TASKS_URL
# {task_id : AsyncTask}

storage_tasks = {}

# relationship between upload task and filesystem
# {hash_id : {'user':user,'system':system,'target':path,'source':fileName,'status':status_code, hash_id':task_id}}
uploaded_files = {}

# debug on console
debug = os.environ.get("F7T_DEBUG_MODE", None)


app = Flask(__name__)

def file_to_str(fileName):

    str_file = ""
    try:
        fileObj = open(fileName,"r")
        str_file = fileObj.read()
        fileObj.close()
        return str_file

    except IOError as e:
        app.logger.error(e)
        return ""


def str_to_file(str_file,dir_name,file_name):
    try:
        if not os.path.exists(dir_name):
            app.logger.info(f"Created temp directory for certs in {dir_name}")
            os.makedirs(dir_name)

        file_str = open(f"{dir_name}/{file_name}","w")
        file_str.write(str_file)
        file_str.close()
        app.logger.info(f"File written in {dir_name}/{file_name}")
    except IOError as e:
        app.logger.error("Couldn't write file {dir_name}/{file_name}")
        app.logger.error(e)



def os_to_fs(task_id):
    upl_file = uploaded_files[task_id]
    system_name = upl_file["system_name"]
    system_addr = upl_file["system_addr"]
    username = upl_file["user"]
    objectname = upl_file["source"]


    try:

        action = upl_file["msg"]["action"]
        
        # certificate is encrypted with CERT_CIPHER_KEY key
        # here is decrypted
        cert = upl_file["msg"]["cert"]
        cipher = Fernet(CERT_CIPHER_KEY)
        # the decryption process produces a byte type
        # remember that is stored as str not as byte in the JSON
        pub_cert = cipher.decrypt(cert[0].encode('utf-8')).decode('utf-8')


        # cert_pub in 0 /user-key-cert.pub
        # temp-dir in 1
        # get tmp directory
        td = cert[1]

        app.logger.info(f"Temp dir: {td}")

        if not os.path.exists(td):
            # retrieve public certificate and store in temp dir location
            str_to_file(pub_cert,td,"user-key-cert.pub")

            # user public and private key should be in Storage / path, symlinking in order to not use the same key at the same time
            os.symlink(os.getcwd() + "/user-key.pub", td + "/user-key.pub")  # link on temp dir
            os.symlink(os.getcwd() + "/user-key", td + "/user-key")  # link on temp dir

            # stat.S_IRUSR -> owner has read permission
            os.chmod(td + "/user-key-cert.pub", stat.S_IRUSR)

        cert_list = [f"{td}/user-key-cert.pub", f"{td}/user-key.pub", f"{td}/user-key", td]

        # start download from OS to FS
        update_task(task_id,None,"storage",async_task.ST_DWN_BEG)

        # execute download
        result = exec_remote_command(username, system_name, system_addr, "", "storage_cert", cert_list)

        # if no error, then download is complete
        if result["error"] == 0:
            update_task(task_id, None,"storage", async_task.ST_DWN_END)
            # delete upload request
            del uploaded_files[task_id]

            # must be deleted after object is moved to storage
            staging.delete_object(containername=username,prefix=task_id,objectname=objectname)

        # if error, should be prepared for try again
        else:
            app.logger.error(result["msg"])
            upl_file["status"] = async_task.ST_DWN_ERR
            uploaded_files[task_id] = upl_file
            update_task(task_id,None,"storage",async_task.ST_DWN_ERR,result["msg"])

    except Exception as e:
        app.logger.error(e)


# asynchronous check of upload_files to declare which is downloadable to FS
def check_upload_files():

    global staging

    while True:
        
        # Get updated task status from Tasks microservice DB backend (TaskPersistence)
        get_upload_unfinished_tasks()

        # Timestampo for logs
        timestamp = time.asctime( time.localtime(time.time()) )
        
        app.logger.info(f"Check files in Object Storage {timestamp}")
        app.logger.info(f"Pendings uploads: {len(uploaded_files)}")

        
        # create STATIC auxiliary upload list in order to avoid "RuntimeError: dictionary changed size during iteration"
        # (this occurs since upload_files dictionary is shared between threads and since Python3 dict.items() trigger that error)
        upl_list= [(task_id, upload) for task_id,upload in uploaded_files.items()]

        for task_id,upload in upl_list:
            #checks if file is ready or not for download to FileSystem
            try:

                task_status = async_task.status_codes[upload['status']]

                app.logger.info(f"Status of {task_id}: {task_status}")
                
                #if upload["status"] in [async_task.ST_URL_REC,async_task.ST_DWN_ERR] :
                if upload["status"] == async_task.ST_URL_REC:
                    app.logger.info(f"Task {task_id} -> File ready to upload or already downloaded")

                    upl = uploaded_files[task_id]
                    app.logger.info(upl)

                    containername = upl["user"]
                    prefix = task_id
                    objectname = upl["source"]
                    
                    if not staging.is_object_created(containername,prefix,objectname):
                        app.logger.info(f"{containername}/{prefix}/{objectname} isn't created in staging area, continue polling")
                        continue

                    # confirms that file is in OS (auth_header is not needed)
                    update_task(task_id, None, "storage",async_task.ST_UPL_CFM)
                    upload["status"] = async_task.ST_UPL_CFM
                    uploaded_files["task_id"] = upload
                    os_to_fs_task = threading.Thread(target=os_to_fs,args=(task_id,))
                    os_to_fs_task.start()
                # if the upload to OS is done but the download to FS failed, then resume
                elif upload["status"] == async_task.ST_DWN_ERR:
                    upl = uploaded_files[task_id]
                    containername = upl["user"]
                    prefix = task_id
                    objectname = upl["source"]
                    # if file has been deleted from OS, then erroneous upload process. Restart.
                    if not staging.is_object_created(containername,prefix,objectname):
                        app.logger.info(f"{containername}/{prefix}/{objectname} isn't created in staging area, task marked as erroneous")
                        update_task(task_id, None, "storage",async_task.ERROR, "File was deleted from staging area. Start a new upload process")
                        upload["status"] = async_task.ERROR
                        continue

                    # if file is still in OS, proceed to new download to FS
                    update_task(task_id, None, "storage",async_task.ST_DWN_BEG)
                    upload["status"] = async_task.ST_DWN_BEG
                    uploaded_files["task_id"] = upload
                    os_to_fs_task = threading.Thread(target=os_to_fs,args=(task_id,))
                    os_to_fs_task.start()
            except Exception as e:
                #app.logger.info("Not ready to upload file")
                continue
            
        time.sleep(STORAGE_POLLING_INTERVAL)



# async task for download large files
# user: user in the posix file system
# system: system in which the file will be stored (REMOVE later)
# sourcePath: path in FS where the object is
# task_id: async task id given for Tasks microservice

def download_task(auth_header,system_name, system_addr,sourcePath,task_id):
    object_name = sourcePath.split("/")[-1]
    global staging

    # check if staging area token is valid
    if not staging.is_token_valid():
        if not staging.authenticate():
            msg = "Staging area auth error"
            update_task(task_id, auth_header,"storage", async_task.ERROR, msg)
            return

    # create container if it doesn't exists:
    container_name = get_username(auth_header)

    if not staging.is_container_created(container_name):
        errno = staging.create_container(container_name)

        if errno == -1:
            msg="Could not create container {container_name} in Staging Area ({staging_name})".format(container_name=container_name, staging_name=staging.get_object_storage())
            update_task(task_id, auth_header,"storage", async_task.ERROR, msg)
            return

    # upload file to swift
    object_prefix = task_id

    upload_url = staging.create_upload_form(sourcePath, container_name, object_prefix, STORAGE_TEMPURL_EXP_TIME, STORAGE_MAX_FILE_SIZE)

    # advice Tasks that upload begins:
    update_task(task_id, auth_header,"storage", async_task.ST_UPL_BEG)

    # upload starts:
    res = exec_remote_command(auth_header,system_name, system_addr,upload_url["command"])

    # if upload to SWIFT fails:
    if res["error"] != 0:
        msg = "Upload to Staging area has failed. Object: {object_name}".format(object_name=object_name)

        error_str = res["msg"]
        if in_str(error_str,"OPENSSH"):
            error_str = "User does not have permissions to access machine"
        msg = f"{msg}. {error_str}"

        app.logger.error(msg)
        update_task(task_id, auth_header, "storage",async_task.ST_UPL_ERR, msg)
        return


    # get Download Temp URL with [seconds] time expiration
    # create temp url for file: valid for STORAGE_TEMPURL_EXP_TIME seconds
    temp_url = staging.create_temp_url(container_name, object_prefix, object_name, STORAGE_TEMPURL_EXP_TIME)

    # if error raises in temp url creation:
    if temp_url == None:
        msg = "Temp URL creation failed. Object: {object_name}".format(object_name=object_name)
        update_task(task_id, auth_header,"storage", async_task.ERROR, msg)
        return

    # if succesfully created: temp_url in task with success status
    update_task(task_id, auth_header,"storage",async_task.ST_UPL_END, temp_url)
    retval = staging.delete_object_after(containername=container_name,prefix=object_prefix,objectname=object_name,ttl=STORAGE_TEMPURL_EXP_TIME)

    if retval == 0:
        app.logger.info("Setting {seconds} [s] as X-Delete-After".format(seconds=STORAGE_TEMPURL_EXP_TIME))
    else:
        app.logger.error("Object couldn't be marked as X-Delete-After")



# download large file, returns temp url for downloading
@app.route("/xfer-external/download", methods=["POST"])
@check_auth_header
def download_request():

    auth_header = request.headers[AUTH_HEADER_NAME]
        
    system_addr = EXT_TRANSFER_MACHINE_INTERNAL
    system_name = EXT_TRANSFER_MACHINE_PUBLIC
    sourcePath = request.form["sourcePath"]  # path file in cluster

    if sourcePath == None or sourcePath == "":
        data = jsonify(error="Source path not set in request")
        return data, 400

    # checks if sourcePath is a valid path
    check = is_valid_file(sourcePath, auth_header, system_name, system_addr)


    if not check["result"]:
        return jsonify(description="sourcePath error"), 400, check["headers"]
    

    # obtain new task from Tasks microservice
    task_id = create_task(auth_header, service="storage")

    # couldn't create task
    if task_id == -1:
        data = jsonify(error="Couldn't create task")
        return data, 400
    
    # asynchronous task creation
    aTask = threading.Thread(target=download_task,
                             args=(auth_header, system_name, system_addr, sourcePath, task_id))

    storage_tasks[task_id] = aTask

    try:
        update_task(task_id, auth_header,"storage", async_task.QUEUED)

        storage_tasks[task_id].start()

        task_url = "{kong_url}/tasks/{task_id}".format(kong_url=KONG_URL, task_id=task_id)

        data = jsonify(success="Task created", task_url=task_url, task_id=task_id)
        return data, 201

    except Exception as e:
        data = jsonify(error=e)
        return data, 400


# invalidate temp URLs
# parameters:
# - X-Task-Id: task id of the transfer related to the URL that wants to be invalidated
@app.route("/xfer-external/invalidate", methods=["POST"])
@check_auth_header
def invalidate_request():
    try:

        task_id = request.headers["X-Task-Id"]
    except KeyError as e:
        return jsonify(error="Header X-Task-Id missing"), 400

    auth_header = request.headers[AUTH_HEADER_NAME]

    # search if task belongs to the user
    task_status = get_task_status(task_id, auth_header)
    
    if task_status == -1:
        return jsonify(error="Invalid X-Task-Id"), 400
    

    containername = get_username(auth_header)
    prefix        = task_id

    objects = staging.list_objects(containername,prefix)

    for objectname in objects:

        error = staging.delete_object(containername,prefix,objectname)

        if error == -1:
            return jsonify(error="Could not invalidate URL"), 400

    return jsonify(success="URL invalidated successfully"), 201




    

# async task for upload large files
# user: user in the posix file system
# system: system in which the file will be stored (REMOVE later)
# targetPath: absolute path in which to store the file
# sourcePath: absolute path in local FS
# task_id: async task_id created with Tasks microservice
def upload_task(auth_header,system_name, system_addr,targetPath,sourcePath,task_id):

    fileName = sourcePath.split("/")[-1]

    # container to bind:
    container_name = get_username(auth_header)

    # change hash_id for task_id since is not longer needed for (failed) redirection
    uploaded_files[task_id] = {"user": container_name,
                               "system_name": system_name,
                               "system_addr": system_addr,
                               "target": targetPath,
                               "source": fileName,
                               "status": async_task.ST_URL_ASK,
                               "hash_id": task_id}

    data = uploaded_files[task_id]

    global staging
    data["msg"] = "Waiting for Presigned URL to upload file to staging area ({})".format(staging.get_object_storage())

    # change to dictionary containing upload data (for backup purpouses) and adding url call
    update_task(task_id, auth_header,"storage", async_task.ST_URL_ASK, data, is_json=True)

    # check if staging token is valid
    if not staging.is_token_valid():
        if not staging.authenticate():
            data = uploaded_files[task_id]
            msg = "Staging Area auth error, try again later"
            data["msg"] = msg
            data["status"] = async_task.ERROR
            update_task(task_id, auth_header, "storage",async_task.ERROR, data, is_json=True)
            return


    # create or return container
    if not staging.is_container_created(container_name):
        errno = staging.create_container(container_name)

        if errno == -1:
            data = uploaded_files[task_id]
            msg="Could not create container {container_name} in Staging Area ({staging_name})".format(container_name=container_name, staging_name=staging.get_object_storage())
            data["msg"] = msg
            data["status"] = async_task.ERROR
            update_task(task_id,auth_header,"storage",async_task.ERROR,data,is_json=True)
            return

    object_prefix = task_id

    # create temporary upload form
    resp = staging.create_upload_form(sourcePath, container_name, object_prefix, STORAGE_TEMPURL_EXP_TIME, STORAGE_MAX_FILE_SIZE)
    data = uploaded_files[task_id]

    # create download URL for later download from Object Storage to filesystem
    app.logger.info("Creating URL for later download")
    download_url = staging.create_temp_url(container_name, object_prefix, fileName, STORAGE_TEMPURL_EXP_TIME)

    # create certificate for later download from OS to filesystem
    app.logger.info("Creating certificate for later download") 
    options = f"-q -O {targetPath}/{fileName} -- '{download_url}'"
    exp_time = STORAGE_TEMPURL_EXP_TIME
    certs = create_certificate(auth_header, system_name, system_addr, "wget", options, exp_time)
    # certs = create_certificates(auth_header,system,command="wget",options=urllib.parse.quote(options),exp_time=STORAGE_TEMPURL_EXP_TIME)

    if not certs[0]:
        data = uploaded_files[task_id]
        msg="Could not create credentials for download from Staging Area to filesystem"
        app.logger.error(msg)
        data["msg"] = msg
        data["status"] = async_task.ERROR
        update_task(task_id,auth_header,"storage",async_task.ERROR,data,is_json=True)
        return

    # converts file to string to store in Tasks
    cert_pub = file_to_str(fileName=certs[0])
    # key_pub  = file_to_str(fileName=certs[1])
    # key_priv = file_to_str(fileName=certs[2])
    temp_dir = certs[3]

    # encrypt certificate with CERT_CIPHER_KEY key     
    cipher = Fernet(CERT_CIPHER_KEY)
    # data to be encrypted should be encoded to bytes
    # in order to save it as json, the cert encrypted should be decoded to string
    cert_pub_enc = cipher.encrypt(cert_pub.encode('utf-8')).decode('utf-8')


    resp["download_url"] = download_url
    resp["action"] = f"wget {options}"
    resp["cert"] =  [cert_pub_enc, temp_dir]

    data["msg"] = resp
    data["status"] = async_task.ST_URL_REC

    app.logger.info("Cert and url created correctly")
    
    update_task(task_id,auth_header,"storage",async_task.ST_URL_REC,data,is_json=True)

    return


# upload API entry point:
@app.route("/xfer-external/upload",methods=["POST"])
@check_auth_header
def upload_request():
    
    auth_header = request.headers[AUTH_HEADER_NAME]

    system_addr = EXT_TRANSFER_MACHINE_INTERNAL
    system_name = EXT_TRANSFER_MACHINE_PUBLIC


    targetPath   = request.form["targetPath"] # path to save file in cluster
    sourcePath   = request.form["sourcePath"] # path from the local FS


    if system_addr == None or system_addr == "":
        data = jsonify(error="System not set in request")
        return data, 400

    if targetPath == None or targetPath == "":
        data = jsonify(error="Target path not set in request")
        return data, 400

    
    if sourcePath == None or sourcePath == "":
        data = jsonify(error="Source path not set in request")
        return data, 400

    # checks if sourcePath is a valid path
    check = is_valid_dir(targetPath, auth_header, system_name, system_addr)

    if not check["result"]:
        return jsonify(description="sourcePath error"), 400, check["headers"]

    # obtain new task from Tasks microservice
    task_id = create_task(auth_header,service="storage")

    if task_id == -1:
        return jsonify(error="Error creating task"), 400
   

    # asynchronous task creation
    try:
        update_task(task_id, auth_header, "storage",async_task.QUEUED)

        aTask = threading.Thread(target=upload_task,
                             args=(auth_header,system_name, system_addr,targetPath,sourcePath,task_id))

        storage_tasks[task_id] = aTask

        storage_tasks[task_id].start()

        task_url = "{kong_url}/tasks/{task_id}".format(kong_url=KONG_URL,task_id=task_id)

        data = jsonify(success="Task created",task_url=task_url,task_id=task_id)
        return data, 201

    except Exception as e:
        data = jsonify(error=e.message)
        return data, 400



# use wget to download file from download_url created with swift
def get_file_from_storage(auth_header,system_name, system_addr,path,download_url,fileName):

    app.logger.info(f"Trying downloading {download_url} from Object Storage to {system_name}")
                    

    # wget to be executed on cluster side:
    action = f"wget -q -O {path}/{fileName} -- \"{download_url}\" "

    app.logger.info(action)

    retval = exec_remote_command(auth_header,system_name, system_addr,action)

    return retval



## upload callback asynchronous task: has_id and task_id
def upload_finished_task(auth_header, system_name, system_addr, targetPath, sourcePath, hash_id):

    global staging

    if not staging.is_token_valid():
        if not staging.authenticate():
            msg = "Staging area auth error"
            update_task(hash_id, auth_header,"storage", async_task.ERROR, msg)
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
        update_task(hash_id, auth_header, "storage",async_task.ST_DWN_ERR,data,is_json=True)
        return

    app.logger.info("[TASK_ID: {task_id}] Temp URL: {tempUrl}".format(task_id=hash_id,tempUrl=temp_url))
    data = uploaded_files[hash_id]

    # register download to server started
    update_task(hash_id,auth_header,"storage", async_task.ST_DWN_BEG, data, is_json=True)
    res = get_file_from_storage(auth_header,system_name, system_addr,targetPath,temp_url,sourcePath) #download file to system

    # result {"error": "error_msg"}
    if res["error"] != 0:
        app.logger.error("Error in download from Staging area to Server")
        app.logger.error(res["error"])
        app.logger.error(res["msg"])
        msg = res["msg"]
        data["msg"] = msg
        update_task(hash_id,auth_header,"storage",async_task.ST_DWN_ERR, data, is_json=True)
        #return jsonify(error=res["msg"])

    else:
        # update task with success signal
        update_task(hash_id, auth_header,"storage",async_task.ST_DWN_END,data,is_json=True)

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
        system_addr = data["system_addr"]
        system_name = data["system_name"]
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

        update_task(hash_id, auth_header,"storage", async_task.ST_UPL_CFM, data, is_json=True)

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
        update_task(hash_id, auth_header, "storage",async_task.ST_DWN_BEG, data, is_json=True)

        aTask = threading.Thread(target=upload_finished_task,
                                 args=(auth_header,system_name,system_addr,target,sourcePath,hash_id,))

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

        sbatch_file.write("#! /bin/bash -l\n")
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
@check_auth_header
def internal_cp():
    return internal_operation(request, "cp")

# Internal mv transfer via SLURM with xfer partition:
@app.route("/xfer-internal/mv", methods=["POST"])
@check_auth_header
def internal_mv():
    return internal_operation(request, "mv")


# Internal rsync transfer via SLURM with xfer partition:
@app.route("/xfer-internal/rsync", methods=["POST"])
@check_auth_header
def internal_rsync():
    return internal_operation(request, "rsync")


# Internal rm transfer via SLURM with xfer partition:
@app.route("/xfer-internal/rm", methods=["POST"])
@check_auth_header
def internal_rm():
    return internal_operation(request, "rm")


# common code for internal cp, mv, rsync, rm
def internal_operation(request, command):

    auth_header = request.headers[AUTH_HEADER_NAME]
    
    try:
        targetPath = request.form["targetPath"]  # path to save file in cluster
        if targetPath == "":
            return jsonify(error="targetPath is empty"), 400    
    except:
        app.logger.error("targetPath not specified")
        return jsonify(error="targetPath not specified"), 400

    # using actual_command to add options to check sanity of the command to be executed
    actual_command = ""
    if command in ['cp', 'mv', 'rsync']:
        try:
            sourcePath = request.form["sourcePath"]  # path to get file in cluster
            if sourcePath == "":
                return jsonify(error="sourcePath is empty"), 400
        except:
            app.logger.error("sourcePath not specified")
            return jsonify(error="sourcePath not specified"), 400
        if command == "cp":
            actual_command = "cp --force -dR --preserve=all -- "
        elif command == "mv":
            actual_command = "mv --force -- "
        else:
            actual_command = "rsync -av -- "
    elif command == "rm":
        # for 'rm' there's no source, set empty to call exec_internal_command(...)
        sourcePath = ""
        actual_command = "rm -rf -- "
    else:
        return jsonify(error=f"Command {command} not allowed"), 400

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

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(STORAGE_JOBS_MACHINE)
    system_addr = SYS_INTERNALS[system_idx]

    # check if machine is accessible by user:
    # exec test remote command
    resp = exec_remote_command(auth_header, STORAGE_JOBS_MACHINE, system_addr, "true")

    if resp["error"] != 0:
        error_str = resp["msg"]
        if resp["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(description=f"Failed to submit {command} job"), 400, header
        if in_str(error_str,"Permission") or in_str(error_str,"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description=f"Failed to submit {command} job"), 404, header

    retval = exec_internal_command(auth_header, actual_command, sourcePath, targetPath, jobName, jobTime, stageOutJobId)

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

    auth_header = request.headers[AUTH_HEADER_NAME]

    files = {'file': open(fileName, 'rb')}

    try:
        req = requests.post("{compute_url}/jobs/upload".
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
        SWIFT_URL = os.environ.get("F7T_SWIFT_URL")
        SWIFT_API_VERSION = os.environ.get("F7T_SWIFT_API_VERSION")
        SWIFT_ACCOUNT = os.environ.get("F7T_SWIFT_ACCOUNT")
        SWIFT_USER = os.environ.get("F7T_SWIFT_USER")
        SWIFT_PASS = os.environ.get("F7T_SWIFT_PASS")

        url = "{swift_url}/{swift_api_version}/AUTH_{swift_account}".format(
            swift_url=SWIFT_URL, swift_api_version=SWIFT_API_VERSION, swift_account=SWIFT_ACCOUNT)

        staging = Swift(url=url, user=SWIFT_USER, passwd=SWIFT_PASS, secret=SECRET_KEY)

    elif OBJECT_STORAGE == "s3v2":
        app.logger.info("Into s3v2")
        from s3v2OS import S3v2

        # For S#:
        S3_URL = os.environ.get("F7T_S3_URL")
        S3_ACCESS_KEY = os.environ.get("F7T_S3_ACCESS_KEY")
        S3_SECRET_KEY = os.environ.get("F7T_S3_SECRET_KEY")

        staging = S3v2(url=S3_URL, user=S3_ACCESS_KEY, passwd=S3_SECRET_KEY)

    elif OBJECT_STORAGE == "s3v4":
        app.logger.info("Into s3v4")
        from s3v4OS import S3v4

        # For S#:
        S3_URL = os.environ.get("F7T_S3_URL")
        S3_ACCESS_KEY = os.environ.get("F7T_S3_ACCESS_KEY")
        S3_SECRET_KEY = os.environ.get("F7T_S3_SECRET_KEY")

        staging = S3v4(url=S3_URL, user=S3_ACCESS_KEY, passwd=S3_SECRET_KEY)

    else:
        app.logger.warning("No Object Storage for staging area was set.")

def get_upload_unfinished_tasks():

    # cleanup upload dictionary
    global uploaded_files
    uploaded_files = {}
    
    
    app.logger.info("Staging Area Used: {}".format(staging.url))
    app.logger.info("ObjectStorage Technology: {}".format(staging.get_object_storage()))
    
    try:
        # query Tasks microservice for previous tasks. Allow 30 seconds to answer
        retval=requests.get("{tasks_url}/taskslist".format(tasks_url=TASKS_URL), timeout=30)

        if not retval.ok:
            app.logger.error("Error getting tasks from Tasks microservice")
            app.logger.warning("TASKS microservice is down")
            app.logger.warning("STORAGE microservice will not be fully functional")
            return

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
                    task["description"] = "Storage has been restarted, process will be resumed"

                    update_task(task["hash_id"], "","storage", async_task.ST_DWN_ERR, data, is_json=True)

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


def init_storage():
    # should check Tasks tasks than belongs to storage

    create_staging()
    get_upload_unfinished_tasks()
    


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

    # aynchronously checks uploaded_files for complete download to FS
    upload_check = threading.Thread(target=check_upload_files)
    upload_check.start()


    app.run(debug=debug, host='0.0.0.0', use_reloader=False, port=STORAGE_PORT)
