#
#  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from flask import Flask, request, jsonify, g
from werkzeug.middleware.profiler import ProfilerMiddleware
import json, tempfile, os

import logging

import async_task
import threading
# common functions
from cscs_api_common import check_auth_header, delete_task, get_username
from cscs_api_common import create_task, update_task, get_task_status
from cscs_api_common import exec_remote_command
from cscs_api_common import create_certificate
from cscs_api_common import in_str
from cscs_api_common import is_valid_file, is_valid_dir, check_command_error, get_boolean_var, get_null_var, validate_input, setup_logging
from cscs_api_common import extract_command

from schedulers import JobScript, factory_scheduler

import requests

import stat
from cryptography.fernet import Fernet
import time
from flask_opentracing import FlaskTracing
from jaeger_client import Config
import opentracing

## READING environment vars

### SSL parameters
SSL_ENABLED = get_boolean_var(os.environ.get("F7T_SSL_ENABLED", True))
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_KEY = os.environ.get("F7T_SSL_KEY", "")

F7T_SCHEME_PROTOCOL = ("https" if SSL_ENABLED else "http")

# Internal microservices communication
## certificator
CERTIFICATOR_HOST = os.environ.get("F7T_CERTIFICATOR_HOST","127.0.0.1")
CERTIFICATOR_PORT = os.environ.get("F7T_CERTIFICATOR_PORT","5000")
CERTIFICATOR_URL = f"{F7T_SCHEME_PROTOCOL}://{CERTIFICATOR_HOST}:{CERTIFICATOR_PORT}"
## tasks
TASKS_HOST = os.environ.get("F7T_TASKS_HOST","127.0.0.1")
TASKS_PORT = os.environ.get("F7T_TASKS_PORT","5003")
TASKS_URL = f"{F7T_SCHEME_PROTOCOL}://{TASKS_HOST}:{TASKS_PORT}"
## compute
COMPUTE_HOST = os.environ.get("F7T_COMPUTE_HOST","127.0.0.1")
COMPUTE_PORT = os.environ.get("F7T_COMPUTE_PORT","5006")
COMPUTE_URL = f"{F7T_SCHEME_PROTOCOL}://{COMPUTE_HOST}:{COMPUTE_PORT}"

## local port for microservice
STORAGE_PORT     = os.environ.get("F7T_STORAGE_PORT", "5002")

AUTH_HEADER_NAME = os.environ.get("F7T_AUTH_HEADER_NAME","Authorization")

# SYSTEMS_PUBLIC: list of allowed systems
# remove quotes and split into array
SYSTEMS_PUBLIC  = os.environ.get("F7T_SYSTEMS_PUBLIC_NAME","").strip('\'"').split(";")
# internal machines to submit/query jobs
SYSTEMS_INTERNAL_COMPUTE   = os.environ.get("F7T_SYSTEMS_INTERNAL_COMPUTE_ADDR", os.environ.get("F7T_SYSTEMS_INTERNAL_ADDR","")).strip('\'"').split(";")
# Machine with filesystems where to download or upload files:
SYSTEMS_INTERNAL_STORAGE = os.environ.get("F7T_SYSTEMS_INTERNAL_STORAGE_ADDR", os.environ.get("F7T_SYSTEMS_INTERNAL_ADDR","")).strip('\'"').split(";")
# Machine to send xfer-internal jobs, as defined in SYSTEMS_PUBLIC
STORAGE_JOBS_MACHINE = os.environ.get("F7T_STORAGE_JOBS_MACHINE", os.environ.get("F7T_SYSTEMS_PUBLIC_NAME","")).strip('\'"').split(";")

###### ENV VAR FOR DETECT TECHNOLOGY OF STAGING AREA:
OBJECT_STORAGE = os.environ.get("F7T_OBJECT_STORAGE", "s3v4").strip('\'"')

OS_AUTH_URL             = os.environ.get("F7T_OS_AUTH_URL", "")
OS_IDENTITY_PROVIDER    = os.environ.get("F7T_OS_IDENTITY_PROVIDER", "")
OS_IDENTITY_PROVIDER_URL= os.environ.get("F7T_OS_IDENTITY_PROVIDER_URL", "")
OS_PROTOCOL             = os.environ.get("F7T_OS_PROTOCOL","openid")
OS_PROJECT_ID           = os.environ.get("F7T_OS_PROJECT_ID", "")

# Detect scheduler object type
STORAGE_SCHEDULER = os.environ.get("F7T_STORAGE_SCHEDULER", os.environ.get("F7T_COMPUTE_SCHEDULER", "Slurm"))

# Scheduller partition used for internal transfers, one per public system
XFER_PARTITION = os.environ.get("F7T_XFER_PARTITION", "").strip('\'"').split(";")

# Scheduller constraint used for internal transfers, one per public system
XFER_CONSTRAINT = os.environ.get("F7T_XFER_CONSTRAINT", "").strip('\'"').split(";")

# use project account in submission
# F7T_USE_SLURM_ACCOUNT is deprecated so we use it only in case F7T_USE_SCHED_PROJECT is not set
USE_SCHED_PROJECT = get_boolean_var(
    os.environ.get("F7T_USE_SCHED_PROJECT", os.environ.get("F7T_USE_SLURM_ACCOUNT", False))
)

# Expiration time for temp URLs in seconds, by default 7 days
STORAGE_TEMPURL_EXP_TIME = int(os.environ.get("F7T_STORAGE_TEMPURL_EXP_TIME", "604800").strip('\'"'))
# max file size for temp URLs in MegaBytes, by default 5120 MB = 5 GB
STORAGE_MAX_FILE_SIZE = int(os.environ.get("F7T_STORAGE_MAX_FILE_SIZE", "5120").strip('\'"'))
# for use on signature of URL it must be in bytes (MB*1024*1024 = Bytes)
STORAGE_MAX_FILE_SIZE *= 1024*1024

UTILITIES_TIMEOUT = int(os.environ.get("F7T_UTILITIES_TIMEOUT", "5").strip('\'"'))

STORAGE_POLLING_INTERVAL = int(os.environ.get("F7T_STORAGE_POLLING_INTERVAL", "60").strip('\'"'))
CERT_CIPHER_KEY = os.environ.get("F7T_CERT_CIPHER_KEY", "").strip('\'"').encode('utf-8')



TRACER_HEADER = "uber-trace-id"

# aynchronous tasks: upload & download --> http://TASKS_URL
# {task_id : AsyncTask}

storage_tasks = {}

# relationship between upload task and filesystem
# {hash_id : {'user':user,'system':system,'target':path,'source':fileName,'status':status_code, 'hash_id':task_id, 'trace_id':trace_id}}
uploaded_files = {}

# DEBUG_MODE on console
DEBUG_MODE = get_boolean_var(os.environ.get("F7T_DEBUG_MODE", False))

app = Flask(__name__)
profiling_middle_ware = ProfilerMiddleware(app.wsgi_app,
                                           restrictions=[15],
                                           filename_format="storage.{method}.{path}.{elapsed:.0f}ms.{time:.0f}.prof",
                                           profile_dir='/var/log/profs')

logger = setup_logging(logging, 'storage')

JAEGER_AGENT = os.environ.get("F7T_JAEGER_AGENT", "").strip('\'"')
if JAEGER_AGENT != "":
    config = Config(
        config={'sampler': {'type': 'const', 'param': 1 },
            'local_agent': {'reporting_host': JAEGER_AGENT, 'reporting_port': 6831 },
            'logging': True,
            'reporter_batch_size': 1},
            service_name = "storage")
    jaeger_tracer = config.initialize_tracer()
    tracing = FlaskTracing(jaeger_tracer, True, app)
else:
    jaeger_tracer = None
    tracing = None



# asynchronous check of upload_files to declare which is downloadable to FS
def check_upload_files():

    global staging

    while True:

        # Get updated task status from Tasks microservice DB backend (TaskPersistence)
        get_upload_unfinished_tasks()

        app.logger.info(f"Check files in Object Storage - Pendings uploads: {len(uploaded_files)}")

        # create STATIC auxiliary upload list in order to avoid "RuntimeError: dictionary changed size during iteration"
        # (this occurs since upload_files dictionary is shared between threads and since Python3 dict.items() trigger that error)
        upl_list= [(task_id, upload) for task_id,upload in uploaded_files.items()]

        for task_id,upload in upl_list:
            #checks if file is ready or not for download to FileSystem
            try:
                task_status = async_task.status_codes[upload['status']]

                headers = {}
                app.logger.info(f"Status of {task_id}: {task_status}")

                #if upload["status"] in [async_task.ST_URL_REC,async_task.ST_DWN_ERR] :
                if upload["status"] == async_task.ST_URL_REC:
                    app.logger.info(f"Task {task_id} -> File ready to upload or already downloaded")

                    upl = uploaded_files[task_id]

                    containername = upl["user"]
                    prefix = task_id
                    objectname = upl["source"]
                    headers[TRACER_HEADER] = upl['trace_id']

                    if not staging.is_object_created(containername,prefix,objectname):
                        app.logger.info(f"{containername}/{prefix}/{objectname} isn't created in staging area, continue polling")
                        continue

                    # confirms that file is in OS (auth_header is not needed)
                    update_task(task_id, headers, async_task.ST_UPL_CFM, msg=upload, is_json=True)
                    upload["status"] = async_task.ST_UPL_CFM
                    uploaded_files["task_id"] = upload
                    os_to_fs_task = threading.Thread(target=os_to_fs, name=upl['trace_id'], args=(task_id,))
                    os_to_fs_task.start()
                # if the upload to OS is done but the download to FS failed, then resume
                elif upload["status"] == async_task.ST_DWN_ERR:
                    upl = uploaded_files[task_id]
                    containername = upl["user"]
                    prefix = task_id
                    objectname = upl["source"]
                    headers[TRACER_HEADER] = upl['trace_id']
                    # if file has been deleted from OS, then erroneous upload process. Restart.
                    if not staging.is_object_created(containername,prefix,objectname):
                        app.logger.info(f"{containername}/{prefix}/{objectname} isn't created in staging area, task marked as erroneous")
                        update_task(task_id, headers ,async_task.ERROR, "File was deleted from staging area. Start a new upload process")
                        upload["status"] = async_task.ERROR
                        continue

                    # if file is still in OS, proceed to new download to FS
                    update_task(task_id, headers, async_task.ST_DWN_BEG)
                    upload["status"] = async_task.ST_DWN_BEG
                    uploaded_files["task_id"] = upload
                    os_to_fs_task = threading.Thread(target=os_to_fs, name=upl['trace_id'], args=(task_id,))
                    os_to_fs_task.start()
            except Exception as e:
                app.logger.error(type(e), e)
                continue

        time.sleep(STORAGE_POLLING_INTERVAL)


def create_staging():
    # Object Storage object
    global staging

    staging = None

    if OBJECT_STORAGE == "swift":

        app.logger.info("Object Storage selected: SWIFT")

        from swiftOS import Swift

        # Object Storage URL & data:
        SWIFT_PUBLIC_URL = os.environ.get("F7T_SWIFT_PUBLIC_URL")
        SWIFT_PRIVATE_URL = os.environ.get("F7T_SWIFT_PRIVATE_URL", SWIFT_PUBLIC_URL)
        SWIFT_API_VERSION = os.environ.get("F7T_SWIFT_API_VERSION", "v1")
        SWIFT_ACCOUNT = OS_PROJECT_ID
        SWIFT_USER = os.environ.get("F7T_SWIFT_USER")
        SWIFT_PASS = os.environ.get("F7T_SWIFT_PASS")
        # SECRET KEY for temp url without using Token
        SWIFT_SECRET_KEY = os.environ.get("F7T_SWIFT_SECRET_KEY")

        priv_url = f"{SWIFT_PRIVATE_URL}/{SWIFT_API_VERSION}/AUTH_{SWIFT_ACCOUNT}"
        publ_url = f"{SWIFT_PUBLIC_URL}/{SWIFT_API_VERSION}/AUTH_{SWIFT_ACCOUNT}"


        staging = Swift(priv_url=priv_url,publ_url=publ_url, user=SWIFT_USER, passwd=SWIFT_PASS, secret=SWIFT_SECRET_KEY)

    elif OBJECT_STORAGE == "s3v2":
        app.logger.info("Object Storage selected: S3v2")
        from s3v2OS import S3v2

        # For S3:
        S3_PUBLIC_URL  = os.environ.get("F7T_S3_PUBLIC_URL")
        S3_PRIVATE_URL = os.environ.get("F7T_S3_PRIVATE_URL", S3_PUBLIC_URL)
        S3_ACCESS_KEY  = os.environ.get("F7T_S3_ACCESS_KEY")
        S3_SECRET_KEY  = os.environ.get("F7T_S3_SECRET_KEY")
        S3_REGION      = os.environ.get("F7T_S3_REGION", "us-east-1")

        staging = S3v2(priv_url=S3_PRIVATE_URL, publ_url=S3_PUBLIC_URL, user=S3_ACCESS_KEY, passwd=S3_SECRET_KEY)

    elif OBJECT_STORAGE == "s3v4":
        app.logger.info("Object Storage selected: S3v4")
        from s3v4OS import S3v4

        # For S3:
        # For S3:
        S3_PRIVATE_URL = os.environ.get("F7T_S3_PRIVATE_URL")
        # For S3:
        S3_PRIVATE_URL = os.environ.get("F7T_S3_PRIVATE_URL")
        S3_PUBLIC_URL  = os.environ.get("F7T_S3_PUBLIC_URL")
        S3_PRIVATE_URL = os.environ.get("F7T_S3_PRIVATE_URL", S3_PUBLIC_URL)
        S3_ACCESS_KEY  = os.environ.get("F7T_S3_ACCESS_KEY")
        S3_SECRET_KEY  = os.environ.get("F7T_S3_SECRET_KEY")
        S3_REGION      = os.environ.get("F7T_S3_REGION", "us-east-1")
        S3_TENANT      = get_null_var(os.environ.get("F7T_S3_TENANT", None))

        staging = S3v4(priv_url=S3_PRIVATE_URL, publ_url=S3_PUBLIC_URL, user=S3_ACCESS_KEY, passwd=S3_SECRET_KEY, region=S3_REGION, tenant=S3_TENANT)

    else:
        app.logger.warning("No Object Storage for staging area was set.")


def get_upload_unfinished_tasks():
    # cleanup upload dictionary
    global uploaded_files
    uploaded_files = {}

    app.logger.info(f"Staging Area Used: {staging.priv_url} - ObjectStorage Technology: {staging.get_object_storage()}")

    try:
        # query Tasks microservice for previous tasks. Allow 30 seconds to answer

        # only unfinished upload process
        status_code = [async_task.ST_URL_ASK, async_task.ST_URL_REC, async_task.ST_UPL_CFM, async_task.ST_DWN_BEG, async_task.ST_DWN_ERR]
        retval=requests.get(f"{TASKS_URL}/taskslist", json={"service": "storage", "status_code":status_code}, timeout=30, verify=(SSL_CRT if SSL_ENABLED else False))

        if not retval.ok:
            app.logger.error("Error getting tasks from Tasks microservice: query failed with status {retval.status_code}, STORAGE microservice will not be fully functional. Next try will be in {STORAGE_POLLING_INTERVAL} seconds")
            return

        queue_tasks = retval.json()

        # queue_tasks structure: "tasks"{
        #                                  task_{id1}: {..., data={} }
        #                                  task_{id2}: {..., data={} }  }
        # data is the field containing every

        queue_tasks = queue_tasks["tasks"]

        n_tasks = 0

        for key,task in queue_tasks.items():

            #task = json.loads(task)

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
                    headers = {}
                    headers[TRACER_HEADER] = data['trace_id']
                    update_task(task["hash_id"], headers, async_task.ST_DWN_ERR, data, is_json=True)

                uploaded_files[task["hash_id"]] = data

                n_tasks += 1

            except KeyError as e:
                app.logger.error(e)
                app.logger.error(task["data"])
                app.logger.error(key)

            except Exception as e:
                app.logger.error(data)
                app.logger.error(e)
                app.logger.error(type(e))

        app.logger.info(f"Not finished upload tasks recovered from taskpersistance: {n_tasks}")

    except Exception as e:
        app.logger.warning("Error querying TASKS microservice: STORAGE microservice will not be fully functional")
        app.logger.error(e)


def init_storage():
    global scheduler
    # create the scheduler object
    try:
        scheduler = factory_scheduler(STORAGE_SCHEDULER)
        app.logger.info("Scheduler selected: {}".format(STORAGE_SCHEDULER))
    except Exception as ex:
        scheduler = None
        app.logger.exception(ex)
        app.logger.error("No scheduler was set.")

    # should check Tasks tasks than belongs to storage
    create_staging()
    get_upload_unfinished_tasks()

    # aynchronously checks uploaded_files for complete download to FS
    upload_check = threading.Thread(target=check_upload_files, name='storage-check-upload-files')
    upload_check.start()


# checks QueuePersistence and retakes all tasks
init_storage()


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
    headers = {}
    headers[TRACER_HEADER] = upl_file['trace_id']

    try:
        if DEBUG_MODE:
            app.logger.debug(upl_file["msg"])

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
        update_task(task_id, headers, async_task.ST_DWN_BEG,
                    msg={
                        "source": objectname,
                        "target": upl_file["target"],
                        "system_name": system_name,
                        "system_addr": system_addr
                        },
                    is_json=True)

        # execute download
        result = exec_remote_command(username, system_name, system_addr, "", "storage_cert", cert_list, log_command="download")

        # if no error, then download is complete
        if result["error"] == 0:
            update_task(task_id, headers, async_task.ST_DWN_END,
                        msg={
                            "source": objectname,
                            "target": upl_file["target"],
                            "system_name": system_name,
                            "system_addr": system_addr
                            },
                        is_json=True)

            # No need to delete the dictionary, it will be cleaned on next iteration

            # must be deleted after object is moved to storage
            # staging.delete_object(containername=username,prefix=task_id,objectname=objectname)
            # for big files delete_object on SWIFT it consumes a long time and often gives a TimeOut error between system and staging area
            # Therefore, using delete_object_after a few minutes (in this case 5 minutes) will trigger internal staging area
            # mechanism to delete the file automatically and without a need of a connection
            #
            # For s3v2 and s3v4 the removal can be done immediately using staging.delete_object()

            if OBJECT_STORAGE == "swift":
                staging.delete_object_after(containername=username,
                                            prefix=task_id,
                                            objectname=objectname,
                                            ttl=int(time.time())+600)

            else:
                staging.delete_object(containername=username,
                                      prefix=task_id,
                                      objectname=objectname)

        else:
            # if error, should be prepared for try again
            upl_file["status"] = async_task.ST_DWN_ERR
            uploaded_files[task_id] = upl_file

            # update but conserv "msg" as the data for download to OS, to be used for retry in next iteration
            update_task(task_id, headers, async_task.ST_DWN_ERR, msg=upl_file, is_json=True)

    except Exception as e:
        app.logger.error(e)
        update_task(task_id, headers, async_task.ST_DWN_ERR, msg=upl_file, is_json=True)



# async task for download large files
# user: user in the posix file system
# system: system in which the file will be stored (REMOVE later)
# sourcePath: path in FS where the object is
# task_id: async task id given for Tasks microservice

def download_task(headers, system_name, system_addr, sourcePath, task_id):
    object_name = sourcePath.split("/")[-1]
    global staging

    # check if staging area token is valid
    if not staging.renew_token():
        msg = {"error": "Staging area auth error", "source": sourcePath, "system_name": system_name}
        update_task(task_id, headers, async_task.ERROR, msg, is_json=True)
        return

    # create container if it doesn't exists:
    is_username_ok = get_username(headers[AUTH_HEADER_NAME])

    if not is_username_ok["result"]:
        app.logger.error(f"Couldn't extract username from JWT token: {is_username_ok['reason']}")
        msg = {"error": is_username_ok['reason'], "source": sourcePath, "system_name": system_name}
        update_task(task_id, headers, async_task.ERROR, msg, is_json=True)

    container_name = is_username_ok["username"]

    if not staging.is_container_created(container_name):
        errno = staging.create_container(container_name)

        if errno == -1:
            error_msg = f"Could not create container {container_name} in Staging Area ({staging.get_object_storage()})"

            msg = {"error": error_msg, "source": sourcePath, "system_name": system_name}

            update_task(task_id, headers, async_task.ERROR, msg, is_json=True)
            return

    # upload file to swift
    object_prefix = task_id

    upload_url = staging.create_upload_form(sourcePath, container_name, object_prefix, STORAGE_TEMPURL_EXP_TIME, STORAGE_MAX_FILE_SIZE)

    # advice Tasks that upload begins:
    msg = {"source": sourcePath, "system_name": system_name}
    update_task(task_id, headers, async_task.ST_UPL_BEG, msg=msg, is_json=True)

    # upload starts:
    res = exec_remote_command(headers, system_name, system_addr, upload_url["command"], log_command="upload url")

    # if upload to SWIFT fails:
    if res["error"] != 0:
        error_msg = f"Upload to Staging area has failed. Object: {object_name}"


        error_str = res["msg"]
        if in_str(error_str,"OPENSSH"):
            error_str = "User does not have permissions to access machine"
        error_msg = f"{error_msg}. {error_str}"
        msg = {"error": error_msg, "source": sourcePath, "system_name": system_name}

        update_task(task_id, headers, async_task.ST_UPL_ERR, msg,is_json=True)
        return


    # get Download Temp URL with [seconds] time expiration
    # create temp url for file: valid for STORAGE_TEMPURL_EXP_TIME seconds
    temp_url = staging.create_temp_url(container_name, object_prefix, object_name, STORAGE_TEMPURL_EXP_TIME,internal=False)

    # if error raises in temp url creation:
    if temp_url == None:
        error_msg = f"Temp URL creation failed. Object: {object_name}"
        msg = {"error": error_msg, "source": sourcePath, "system_name": system_name}
        update_task(task_id, headers, async_task.ERROR, msg, is_json=True)
        return

    # if succesfully created: temp_url in task with success status
    msg = {"url": temp_url, "source": sourcePath, "system_name": system_name}
    update_task(task_id, headers, async_task.ST_UPL_END, msg, is_json=True)
    # marked deletion from here to STORAGE_TEMPURL_EXP_TIME (default 30 days)
    # this is only needed for SWIFT objects for S3 objects the Lifecycle Policy is set on bucket creation
    if OBJECT_STORAGE == "swift":
        retval = staging.delete_object_after(containername=container_name,
                                             prefix=object_prefix,
                                             objectname=object_name,
                                             ttl=int(time.time()) + STORAGE_TEMPURL_EXP_TIME)

        if retval == 0:
            app.logger.info(f"Setting {STORAGE_TEMPURL_EXP_TIME} [s] as X-Delete-At")
        else:
            app.logger.error("Object couldn't be marked as X-Delete-At")



# download large file, returns temp url for downloading
@app.route("/xfer-external/download", methods=["POST"])
@check_auth_header
def download_request():

    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Failed operation", error="Machine does not exists"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYSTEMS_INTERNAL_STORAGE[system_idx]

    sourcePath = request.form.get("sourcePath", None) # path file in cluster
    v = validate_input(sourcePath)
    if v != "":
        return jsonify(description="Failed to download file", error=f"'sourcePath' {v}"), 400

    [headers, ID] = get_tracing_headers(request)
    # checks if sourcePath is a valid path
    check = is_valid_file(sourcePath, headers, system_name, system_addr)

    if not check["result"]:
        return jsonify(description="sourcePath error"), 400, check["headers"]

    # obtain new task from Tasks microservice
    task_id = create_task(headers, service="storage", system=system_name, init_data={"source": sourcePath, "system_name": system_name})

    # couldn't create task
    if task_id == -1:
        return jsonify(error="Couldn't create task"), 400

    try:
        # asynchronous task creation
        aTask = threading.Thread(target=download_task, name=ID,
                             args=(headers, system_name, system_addr, sourcePath, task_id))

        storage_tasks[task_id] = aTask
        update_task(task_id, headers, async_task.QUEUED)

        storage_tasks[task_id].start()

        task_url = f"/tasks/{task_id}"
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
        if not task_id.isalnum():
            return jsonify(error="Header X-Task-Id is not alphanumeric"), 400
    except KeyError as e:
        return jsonify(error="Header X-Task-Id missing"), 400

    [headers, ID] = get_tracing_headers(request)
    # search if task belongs to the user
    task_status = get_task_status(task_id, headers)

    if task_status == -1:
        return jsonify(error="Invalid X-Task-Id"), 400

    is_username_ok = get_username(headers[AUTH_HEADER_NAME])

    if not is_username_ok["result"]:
        app.logger.error(f"Couldn't extract username from JWT token: {is_username_ok['reason']}")
        return jsonify(error=is_username_ok['reason']), 401

    containername = is_username_ok["username"]
    prefix = task_id

    objects = staging.list_objects(containername, prefix)

    for objectname in objects:

        # error = staging.delete_object(containername,prefix,objectname)
        # replacing delete_object by delete_object_after 5 minutes for SWIFT 
        # objects

        if OBJECT_STORAGE == "swift":
            error = staging.delete_object_after(containername=containername,
                                                prefix=prefix,
                                                objectname=objectname,
                                                ttl=int(time.time())+600)
        else:
            error = staging.delete_object(containername=containername,
                                          prefix=prefix,
                                          objectname=objectname)

        if error == -1:
            return jsonify(error="Could not invalidate URL"), 400

        # if file is invalidated, then delete the task
        if not delete_task(task_id, headers):
            app.logger.warning(f"Task {task_id} couldn't be marked as invalid in database")
        else:
            app.logger.info(f"Task {task_id} marked as invalid in database")


    return jsonify(success="URL invalidated successfully"), 201


# async task for upload large files
# user: user in the posix file system
# system: system in which the file will be stored (REMOVE later)
# targetPath: absolute path in which to store the file
# sourcePath: absolute path in local FS
# task_id: async task_id created with Tasks microservice
def upload_task(headers, system_name, system_addr, targetPath, sourcePath, task_id):

    fileName = sourcePath.split("/")[-1]

    # container to bind:
    is_username_ok = get_username(headers[AUTH_HEADER_NAME])

    if not is_username_ok["result"]:
        app.logger.error(f"Couldn't extract username from JWT token: {is_username_ok['reason']}")
        update_task(task_id, headers, async_task.ERROR, is_username_ok['reason'], is_json=True)

    container_name = is_username_ok["username"]
    ID = headers.get(TRACER_HEADER, '')
    # change hash_id for task_id since is not longer needed for (failed) redirection
    uploaded_files[task_id] = {"user": container_name,
                               "system_name": system_name,
                               "system_addr": system_addr,
                               "target": targetPath,
                               "source": fileName,
                               "status": async_task.ST_URL_ASK,
                               "hash_id": task_id,
                               "trace_id": ID}

    data = uploaded_files[task_id]

    global staging
    data["msg"] = f"Waiting for Presigned URL to upload file to staging area ({staging.get_object_storage()})"

    # change to dictionary containing upload data (for backup purpouses) and adding url call
    update_task(task_id, headers, async_task.ST_URL_ASK, data, is_json=True)

    # check if staging token is valid
    if not staging.renew_token():
        msg = "Staging Area auth error, try again later"
        data["msg"] = msg
        data["status"] = async_task.ERROR
        update_task(task_id, headers, async_task.ERROR, data, is_json=True)
        return

    # create or return container
    if not staging.is_container_created(container_name):
        errno = staging.create_container(container_name)
        if errno == -1:
            msg = f"Could not create container {container_name} in Staging Area ({staging.get_object_storage()})"
            data["msg"] = msg
            data["status"] = async_task.ERROR
            update_task(task_id, headers, async_task.ERROR, data, is_json=True)
            return

    object_prefix = task_id

    # create temporary upload form
    resp = staging.create_upload_form(sourcePath, container_name, object_prefix, STORAGE_TEMPURL_EXP_TIME, STORAGE_MAX_FILE_SIZE, internal=False)

    # create download URL for later download from Object Storage to filesystem
    app.logger.info("Creating URL for later download")
    download_url = staging.create_temp_url(container_name, object_prefix, fileName, STORAGE_TEMPURL_EXP_TIME)

    # create certificate for later download from OS to filesystem
    app.logger.info(f"Creating certificate for later download")
    options = f"-f -s -G -o '{targetPath}' -- '{download_url}'"
    exp_time = STORAGE_TEMPURL_EXP_TIME
    certs = create_certificate(headers, system_name, system_addr, f"ID={ID} curl", options, exp_time)

    if not certs[0]:
        msg = "Could not create certificate for download from Staging Area to filesystem"
        app.logger.error(msg)
        data["msg"] = msg
        data["status"] = async_task.ERROR
        update_task(task_id, headers, async_task.ERROR, data, is_json=True)
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
    resp["action"] = f"curl {options}"
    resp["cert"] =  [cert_pub_enc, temp_dir]

    data["msg"] = resp
    data["status"] = async_task.ST_URL_REC

    app.logger.info("Cert and url created correctly")

    update_task(task_id, headers, async_task.ST_URL_REC, data, is_json=True)

    return


# upload API entry point:
@app.route("/xfer-external/upload",methods=["POST"])
@check_auth_header
def upload_request():

    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Failed operation", error="Machine does not exists"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYSTEMS_INTERNAL_STORAGE[system_idx]

    targetPath = request.form.get("targetPath", None) # path to save file in cluster
    v = validate_input(targetPath)
    if v != "":
        return jsonify(description="Failed to upload file", error=f"'targetPath' {v}"), 400

    sourcePath = request.form.get("sourcePath", None) # path from the local FS
    v = validate_input(sourcePath)
    if v != "":
        return jsonify(description="Failed to upload file", error=f"'sourcePath' {v}"), 400

    [headers, ID] = get_tracing_headers(request)
    # checks if the targetPath is a directory (targetPath = "/path/to/dir") that can be accessed by the user
    check_is_dir = is_valid_dir(targetPath, headers, system_name, system_addr)

    # if so, then the actual targetPath has to include the name extracted from sourcePath
    _targetPath = f"{targetPath}/{sourcePath.split('/')[-1]}"

    if not check_is_dir["result"]:

        # check if targetPath is a file path by extracting last part of the path
        check_is_dir = is_valid_dir("/".join(targetPath.split("/")[:-1]), headers, system_name, system_addr)

        if not check_is_dir["result"]:

            return jsonify(description="Failed to upload file", error="'targetPath' directory not allowed"), 400, check_is_dir["headers"]
        # if targetPath is a file, then no changes need to be done
        _targetPath = targetPath

    # obtain new task from Tasks microservice
    task_id = create_task(headers, service="storage", system=system_name, init_data={"source":sourcePath, "target": _targetPath})

    if task_id == -1:
        return jsonify(error="Error creating task"), 400

    # asynchronous task creation
    try:
        update_task(task_id, headers, async_task.QUEUED)

        aTask = threading.Thread(target=upload_task, name=ID,
                             args=(headers, system_name, system_addr, _targetPath, sourcePath, task_id))

        storage_tasks[task_id] = aTask

        storage_tasks[task_id].start()

        task_url = f"/tasks/{task_id}"

        data = jsonify(success="Task created",task_url=task_url,task_id=task_id)
        return data, 201

    except Exception as e:
        data = jsonify(error=e)
        return data, 400


## Internal Transfer MicroServices:
## cp / rm / mv / rsync using Jobs microservice


# executes system cp/mv/rm or rsync (xfer-internal)
# creates a sbatch file to execute in --partition=xfer
# user_header for user identification
# command = "cp" "mv" "rm" "rsync"
# jobName = --job-name parameter to be used on sbatch command
# jobTime = --time  parameter to be used on sbatch command
# stageOutJobId = value to set in --dependency:afterok parameter
# account = value to set in --account parameter
def exec_internal_command(headers, system_idx, command, jobName, jobTime, stageOutJobId, account):

    try:
        td = tempfile.mkdtemp(prefix="job")
        ID = headers.get(TRACER_HEADER, '')
        if XFER_CONSTRAINT == []:
            constraint = None
        else:
            constraint = XFER_CONSTRAINT[system_idx]

        script_spec = JobScript(
            name=jobName,
            time=jobTime,
            partition=XFER_PARTITION[system_idx],
            command=command,
            dependency_id=stageOutJobId,
            account=account,
            constraint=constraint
        )

        with open(td + "/sbatch-job.sh", "w") as sbatch_file:
            sbatch_file.write(scheduler.script_template(ID, script_spec))

    except IOError as ioe:
        app.logger.error(ioe.message)
        result = {"error": 1, "msg":ioe.message}
        return result

    # create xfer job
    resp = create_xfer_job(SYSTEMS_PUBLIC[system_idx], headers, td + "/sbatch-job.sh")

    try:
        # remove sbatch file and dir
        os.remove(td + "/sbatch-job.sh")
        os.rmdir(td)
    except IOError as ioe:
        app.logger.error(f"Failed to remove temp sbatch file: {ioe.message}")

    return resp


# Internal cp transfer via the scheduler xfer partition:
@app.route("/xfer-internal/cp", methods=["POST"])
@check_auth_header
def internal_cp():
    return internal_operation(request, "cp")

# Internal mv transfer via the scheduler xfer partition:
@app.route("/xfer-internal/mv", methods=["POST"])
@check_auth_header
def internal_mv():
    return internal_operation(request, "mv")


# Internal rsync transfer via the scheduler xfer partition:
@app.route("/xfer-internal/rsync", methods=["POST"])
@check_auth_header
def internal_rsync():
    return internal_operation(request, "rsync")


# Internal rm transfer via the scheduler xfer partition:
@app.route("/xfer-internal/rm", methods=["POST"])
@check_auth_header
def internal_rm():
    return internal_operation(request, "rm")


# Internal compression transfer via the scheduler xfer partition:
@app.route("/xfer-internal/compress", methods=["POST"])
@check_auth_header
def internal_compress():
    return internal_operation(request, "compress")


# Internal extraction transfer via the scheduler xfer partition:
@app.route("/xfer-internal/extract", methods=["POST"])
@check_auth_header
def internal_extract():
    return internal_operation(request, "extract")


# common code for internal cp, mv, rsync, rm
def internal_operation(request, command):

    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Failed operation", error="Machine does not exists"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    # actual machine for submitting Slurm job may be different:
    system_name = STORAGE_JOBS_MACHINE[system_idx]
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYSTEMS_INTERNAL_COMPUTE[system_idx]

    targetPath = request.form.get("targetPath", None)  # path to save file in cluster
    v = validate_input(targetPath)
    if v != "":
        return jsonify(description=f"Error on {command} operation", error=f"'targetPath' {v}"), 400

    [headers, ID] = get_tracing_headers(request)
    # using actual_command to add options to check sanity of the command to be executed
    actual_command = ""
    if command in ['cp', 'mv', 'rsync', 'compress', 'extract']:
        sourcePath = request.form.get("sourcePath", None)  # path to get file in cluster
        v = validate_input(sourcePath)
        if v != "":
            return jsonify(description=f"Error on {command} operation", error=f"'sourcePath' {v}"), 400

        # checks if file to copy, move or rsync (targetPath) is a valid path
        # remove the last part of the path (after last "/" char) to check if the dir can be written by user

        _targetPath = targetPath.split("/")[:-1]
        _targetPath = "/".join(_targetPath)

        app.logger.info(f"_targetPath={_targetPath}")

        if command == "cp":
            actual_command = f"cp --force -dR --preserve=all -- '{sourcePath}' '{targetPath}'"
        elif command == "mv":
            actual_command = f"mv --force -- '{sourcePath}' '{targetPath}'"
        elif command == "rsync":
            actual_command = f"rsync -av -- '{sourcePath}' '{targetPath}'"
        elif command == "compress":
            basedir = os.path.dirname(sourcePath)
            file_path = os.path.basename(sourcePath)
            deref = ""
            if get_boolean_var(request.form.get("dereference", False)):
                deref = "--dereference"

            actual_command = f"tar {deref} -czf '{targetPath}' -C '{basedir}' '{file_path}'"
        else:
            extraction_type = request.form.get("type", "auto")
            actual_command = extract_command(sourcePath, targetPath, type=extraction_type)
            if not actual_command:
                return jsonify(description=f"Error on {command} operation", error=f"Unsupported file format in {sourcePath}."), 400

    elif command == "rm":
        sourcePath = ""
        actual_command = f"rm -rf -- '{targetPath}'"
    else:
        return jsonify(error=f"Command {command} not allowed"), 400

    jobName = request.form.get("jobName", "")
    if jobName == "":
        jobName = command + "-job"
        app.logger.info(f"jobName not found, setting default to: {jobName}")
    else:
        v = validate_input(jobName)
        if v != "":
            return jsonify(description="Invalid jobName", error=f"'jobName' {v}"), 400

    try:
        jobTime = request.form["time"]  # job time, default is 2:00:00 H:M:s
        if not scheduler.check_job_time(jobTime):
            return jsonify(error="Not supported time format"), 400
    except:
        jobTime = "02:00:00"

    stageOutJobId = request.form.get("stageOutJobId", None)  # start after this JobId has finished
    if stageOutJobId != None:
        v = validate_input(stageOutJobId)
        if v != "":
            return jsonify(description="Invalid stageOutJobId", error=f"'stageOutJobId' {v}"), 400

    app.logger.info(f"USE_SCHED_PROJECT: {USE_SCHED_PROJECT}")
    # get "account" parameter, if not found, it is obtained from "id" command
    try:
        account = request.form["account"]
        v = validate_input(account)
        if v != "":
            return jsonify(description="Invalid account", error=f"'account' {v}"), 400
    except:
        if USE_SCHED_PROJECT:
            is_username_ok = get_username(headers[AUTH_HEADER_NAME])

            if not is_username_ok["result"]:
                app.logger.error(f"Couldn't extract username from JWT token: {is_username_ok['reason']}")
                return jsonify(description=f"Failed to submit {command} job", error=is_username_ok['reason']), 401

            username = is_username_ok["username"]

            id_command = f"timeout {UTILITIES_TIMEOUT} id -gn -- {username}"
            resp = exec_remote_command(headers, system_name, system_addr, id_command, trace_id=ID, log_command="id")
            if resp["error"] != 0:
                retval = check_command_error(resp["msg"], resp["error"], f"{command} job")
                return jsonify(description=f"Failed to submit {command} job", error=retval["description"]), retval["status_code"], retval["header"]

            account = resp["msg"]
        else:
            account = None

    # check if machine is accessible by user:
    # exec test remote command
    resp = exec_remote_command(headers, system_name, system_addr, "true", trace_id=ID, log_command=command)

    if resp["error"] != 0:
        error_str = resp["msg"]
        if resp["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(description=f"Failed to submit {command} job"), 400, header
        if in_str(error_str,"Permission") or in_str(error_str,"OPENSSH"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description=f"Failed to submit {command} job"), 404, header

    retval = exec_internal_command(headers, system_idx, actual_command, jobName, jobTime, stageOutJobId, account)

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
def create_xfer_job(machine, headers, fileName):

    files = {'file': open(fileName, 'rb')}

    try:
        headers["X-Machine-Name"] = machine
        req = requests.post(f"{COMPUTE_URL}/jobs/upload",
                            files=files, headers=headers, verify=(SSL_CRT if SSL_ENABLED else False))

        retval = json.loads(req.text)
        if not req.ok:
            return {"error":1,"msg":retval["description"],"desc":retval["error"]}

        return retval

    except Exception as e:
        app.logger.error(e)
        return {"error":1,"msg":e}



@app.route("/status",methods=["GET"])
@check_auth_header
def status():

    app.logger.info("Test status of service")
    # TODO: check backend storage service to truthfully respond this request
    if("X-F7T-PROFILE" in request.headers):
        app.wsgi_app = profiling_middle_ware
        return jsonify(success="profiling activated!"), 200
    else:
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
    if SSL_ENABLED:
        app.run(debug=DEBUG_MODE, host='0.0.0.0', use_reloader=False, port=STORAGE_PORT, ssl_context=(SSL_CRT, SSL_KEY))
    else:
        app.run(debug=DEBUG_MODE, host='0.0.0.0', use_reloader=False, port=STORAGE_PORT)
