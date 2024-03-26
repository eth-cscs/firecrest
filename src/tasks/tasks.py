#
#  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from flask import Flask, request, jsonify, g
from werkzeug.middleware.profiler import ProfilerMiddleware
# task states
import async_task
import os
import logging
from flask_opentracing import FlaskTracing
from jaeger_client import Config

from cscs_api_common import check_auth_header, get_username, check_header, \
    get_boolean_var, setup_logging, validate_input
import tasks_persistence as persistence

AUTH_HEADER_NAME = os.environ.get("F7T_AUTH_HEADER_NAME","Authorization")

TASKS_PORT    = os.environ.get("F7T_TASKS_PORT", 5000)

# redis info:
PERSIST_HOST   = os.environ.get("F7T_PERSIST_HOST", "127.0.0.1")
PERSIST_PORT = os.environ.get("F7T_PERSIST_PORT", "6379")
PERSIST_PWD  = os.environ.get("F7T_PERSIST_PWD")

### SSL parameters
SSL_ENABLED = get_boolean_var(os.environ.get("F7T_SSL_ENABLED", True))
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_KEY = os.environ.get("F7T_SSL_KEY", "")

# expire time in seconds, for squeue or sacct tasks: default: 24hours = 86400 secs
COMPUTE_TASK_EXP_TIME = os.environ.get("F7T_COMPUTE_TASK_EXP_TIME", 86400)

# expire time in seconds, for download/upload the default value is 7 days = 604800 secs
STORAGE_TASK_EXP_TIME = os.environ.get("F7T_STORAGE_TASK_EXP_TIME", os.environ.get("F7T_STORAGE_TEMPURL_EXP_TIME", 604800))

TRACER_HEADER = "uber-trace-id"

DEBUG_MODE = get_boolean_var(os.environ.get("F7T_DEBUG_MODE", False))

# task dict, key is the task_id
tasks = {}


app = Flask(__name__)
profiling_middle_ware = ProfilerMiddleware(app.wsgi_app,
                                           restrictions=[15],
                                           filename_format="tasks.{method}.{path}.{elapsed:.0f}ms.{time:.0f}.prof",
                                           profile_dir='/var/log/profs')

logger = setup_logging(logging, 'tasks')

JAEGER_AGENT = os.environ.get("F7T_JAEGER_AGENT", "").strip('\'"')
if JAEGER_AGENT != "":
    config = Config(
        config={'sampler': {'type': 'const', 'param': 1 },
            'local_agent': {'reporting_host': JAEGER_AGENT, 'reporting_port': 6831 },
            'logging': True,
            'reporter_batch_size': 1},
            service_name = "tasks")
    jaeger_tracer = config.initialize_tracer()
    tracing = FlaskTracing(jaeger_tracer, True, app)
else:
    jaeger_tracer = None
    tracing = None

# redis connection object
r = None

def init_queue():

    global r

    r=persistence.create_connection(host=PERSIST_HOST, port=PERSIST_PORT, passwd=PERSIST_PWD, db=0)

    if r == None:
        app.logger.error("Persistence Database is not functional")
        app.logger.error("Tasks microservice cannot be started")
        return

    # dictionary: [task_id] = {hash_id,status_code,user,data}
    task_list = persistence.get_all_tasks(r)

    # key = task_id ; values = {status_code,user,data}
    for rid, value in task_list.items():

        # task_list has id with format task_id, ie: task_2
        # therefore it must be splitted by "_" char:
        task_id = rid.split("_")[1]

        status  = value["status"]
        user    = value["user"]
        data    = value["data"]
        service = value["service"]

        t = async_task.AsyncTask(task_id,user,service)
        t.set_status(status,data)
        tasks[t.hash_id] = t

# init Redis connection
init_queue()



@app.route("/",methods=["GET"])
@check_auth_header
def list_tasks():
    auth_header = request.headers[AUTH_HEADER_NAME]
    # getting username from auth_header
    is_username_ok = get_username(auth_header)

    if not is_username_ok["result"]:
        app.logger.error(f"Couldn't extract username from JWT token: {is_username_ok['reason']}")
        return jsonify(description=f"Error on JWT token verification: {is_username_ok['reason']}"), 401

    username = is_username_ok["username"]

    task_list = request.args.get("tasks",None)
    if task_list != None:
        v = validate_input(task_list)
        if v != "":
            return jsonify(description="Failed to retrieve tasks information", error=f"'tasks' {v}"), 400
        
        task_list = task_list.split(",")

    user_tasks = {}

    user_tasks = persistence.get_user_tasks(r,username, task_list=task_list)
   
    data = jsonify(tasks=user_tasks)
    return data, 200

# create a new task, response should be task_id of created task
@app.route("/",methods=["POST"])
def create_task():

    # checks if request has service header
    try:
        service = request.headers["X-Firecrest-Service"]

        if service not in ["storage","compute"]:
            return jsonify(description=f"Service {service} is unknown"), 403

    except KeyError:
        return jsonify(description="No service informed"), 403
    
    # checks if the request has the X-Machine-Name header
    system = None
    try:
        system = request.headers["X-Machine-Name"]
    except KeyError:
        app.logger.warning("X-Machine-Name header not set for this task")



    auth_header = request.headers[AUTH_HEADER_NAME]
    is_header_ok = check_header(auth_header)
    if not is_header_ok["result"]:
        return jsonify(description=is_header_ok["reason"]), 401

    # getting username from auth_header
    is_username_ok = get_username(auth_header)

    if not is_username_ok["result"]:
        app.logger.error(f"Couldn't extract username from JWT token: {is_username_ok['reason']}")
        return jsonify(description=f"Couldn't create task. Reason: {is_username_ok['reason']}"), 401

    username = is_username_ok["username"]

    try:
        init_data = request.form.get("init_data")
    except KeyError as ke:
        if DEBUG_MODE:
            app.logger.warning("Not initial data set in the task creation")

    # QueuePersistence connection
    global r

    # incremente the last_task_id in 1 unit
    task_id = persistence.incr_last_task_id(r)

    # if there was a problem getting new task_id from persistence
    if task_id == None:
        return jsonify(description="Couldn't create task"), 400

    # create task with service included

    t = async_task.AsyncTask(task_id=str(task_id), user=username, service=service, system=system,data=init_data)

    tasks[t.hash_id] = t
    if JAEGER_AGENT != "":
        try:
            span = tracing.get_span(request)
            span.set_tag('f7t_task_id', t.hash_id)
        except Exception as e:
            app.logger.info(e)

    exp_time = STORAGE_TASK_EXP_TIME

    if service == "compute":
        exp_time = COMPUTE_TASK_EXP_TIME

    persistence.save_task(r,id=task_id,task=t.get_status(),exp_time=exp_time)

    # {"id":task_id,
    #               "status":async_task.QUEUED,
    #               "msg":async_task.status_codes[async_task.QUEUED]}

    app.logger.info(f"New task created: {t.hash_id}")
    app.logger.info(t.get_status())
    task_url = f"/tasks/{t.hash_id}"

    data = jsonify(hash_id=t.hash_id, task_url=task_url)

    return data, 201



# should return status of the task
@app.route("/<id>",methods=["GET"])
@check_auth_header
def get_task(id):

    auth_header = request.headers[AUTH_HEADER_NAME]

    # getting username from auth_header
    is_username_ok = get_username(auth_header)

    if not is_username_ok["result"]:
        app.logger.error(f"Couldn't extract username from JWT token: {is_username_ok['reason']}")
        return jsonify(description=f"Couldn't retrieve task. Reason: {is_username_ok['reason']}"), 401

    username = is_username_ok["username"]

    # for better knowledge of what this id is
    hash_id = id

    try:
        if not tasks[hash_id].is_owner(username):
            return jsonify(description="Operation not permitted. Invalid task owner."), 403

        task_status=tasks[hash_id].get_status()
        task_status["task_url"] = f"/tasks/{hash_id}"
        data = jsonify(task=task_status)
        return data, 200

    except KeyError:
        data = jsonify(error=f"Task {id} does not exist")
        return  data, 404


# update status of the task with task_id = id
@app.route("/<id>",methods=["PUT"])
def update_task(id):

    if request.is_json:

        try:
            data = request.get_json(force=True)
            status=data["status"]
            msg=data["msg"]

        except Exception as e:
            app.logger.error(type(e))

    else:

        try:
            msg  = request.form["msg"]
        except Exception as e:
            msg = None
            # app.logger.error(e.message)

        status = request.form["status"]

    # for better knowledge of what this id is
    hash_id = id

    # check if task exist
    try:
        current_task=tasks[hash_id]
    except KeyError:
        data = jsonify(error=f"Task {hash_id} does not exist")
        return data, 404

    if JAEGER_AGENT != "":
        try:
            span = tracing.get_span(request)
            span.set_tag('f7t_task_id', hash_id)
        except Exception as e:
            app.logger.info(e)


    # checks if status request is valid:
    if status not in async_task.status_codes:
        data = jsonify(error="Status code error",status=status)
        app.logger.error(data)
        return data, 400


    # if no msg on request, default status msg:
    if msg == None:
        msg = async_task.status_codes[status]

    # update task in memory
    tasks[hash_id].set_status(status=status, data=msg)

    # getting service from task, to set exp_time according to the service
    service = tasks[hash_id].get_internal_status()["service"]

    global r
    exp_time = STORAGE_TASK_EXP_TIME

    if service == "compute":
        exp_time = COMPUTE_TASK_EXP_TIME

    #update task in persistence server
    if not persistence.save_task(r, id=tasks[hash_id].task_id, task=tasks[hash_id].get_internal_status(), exp_time=exp_time):
        app.logger.error("Error saving task")
        app.logger.error(tasks[hash_id].get_internal_status())
        return jsonify(description="Couldn't update task"), 400

    app.logger.info(f"New status for task {hash_id}: {status}")

    data = jsonify(success="task updated")
    return data, 200



@app.route("/<id>", methods=["DELETE"])
@check_auth_header
def delete_task(id):
    auth_header = request.headers[AUTH_HEADER_NAME]

    # getting username from auth_header
    is_username_ok = get_username(auth_header)

    if not is_username_ok["result"]:
        app.logger.error(f"Couldn't extract username from JWT token: {is_username_ok['reason']}")
        return jsonify(description=f"Couldn't delete task. Reason: {is_username_ok['reason']}"), 401

    username = is_username_ok["username"]

    # for better knowledge of what this id is
    hash_id = id

    # if username isn't taks owner, then deny access
    try:
        if not tasks[hash_id].is_owner(username):
            return jsonify(description="Operation not permitted. Invalid task owner."), 403
    except KeyError:
        data = jsonify(error=f"Task {id} does not exist")
        return data, 404

    try:
        global r

        if not persistence.set_expire_task(r,id=tasks[hash_id].task_id,secs=300):
            return jsonify(error=f"Failed to delete task {hash_id} on persistence server"), 400

        data = jsonify(success=f"Task {hash_id} deleted")
        tasks[hash_id].set_status(status=async_task.INVALID, data="")
        return data, 204

    except Exception as e:
        app.logger.error(f"Failed to delete task {hash_id} on persistence server")
        app.logger.error(f"Error: {type(e)}")
        app.logger.error(f"Error: {e}")

        data = jsonify(error=f"Failed to delete task {hash_id} on persistence server")
        return data, 400

#set expiration for task, in case of Jobs list or account info:
@app.route("/expire/<id>",methods=["POST"])
@check_auth_header
def expire_task(id):

    auth_header = request.headers[AUTH_HEADER_NAME]

    # checks if request has service header
    try:
        service = request.headers["X-Firecrest-Service"]

        if service not in ["storage","compute"]:
            return jsonify(description=f"Service {service} is unknown"), 403

    except KeyError:
        return jsonify(description="No service informed"), 403

    # getting username from auth_header
    is_username_ok = get_username(auth_header)

    if not is_username_ok["result"]:
        app.logger.error(f"Couldn't extract username from JWT token: {is_username_ok['reason']}")
        return jsonify(description=f"Couldn't expire task. Reason: {is_username_ok['reason']}"), 401

    username = is_username_ok["username"]

    # for better knowledge of what this id is
    hash_id = id

    # if username isn't taks owner, then deny access
    try:
        if not tasks[hash_id].is_owner(username):
            return jsonify(description="Operation not permitted. Invalid task owner."), 403
    except KeyError:
        data = jsonify(error=f"Task {id} does not exist")
        return data, 404


    exp_time = STORAGE_TASK_EXP_TIME

    if service == "compute":
        exp_time = COMPUTE_TASK_EXP_TIME

    try:
        global r

        app.logger.info(f"Set expiration for task {tasks[hash_id].task_id} - {exp_time} secs")
        if not persistence.set_expire_task(r,id=tasks[hash_id].task_id,secs=exp_time):
            app.logger.warning(f"Task couldn't be marked as expired")
            return jsonify(error="Failed to set expiration time on task in persistence server"), 400

        data = jsonify(success=f"Task expiration time set to {exp_time} secs.")

        return data, 200

    except Exception:
        data = jsonify(Error="Failed to set expiration time on task in persistence server")
        return data, 400


@app.route("/status",methods=["GET"])
@check_auth_header
def status():
    app.logger.info("Test status of service")
    if("X-F7T-PROFILE" in request.headers):
        app.wsgi_app = profiling_middle_ware
        return jsonify(success="profiling activated!"), 200
    else:
        return jsonify(success="ack"), 200
    
    


# entry point for all tasks by all users (only used by internal)
# used by storage for the upload tasks, but it can be used for all tasks status and services
@app.route("/taskslist", methods=["GET"])
def tasklist():

    global r

    app.logger.info("Getting service tasks")

    json = request.json

    if json == None:
        app.logger.error("json attribute not passed to the service")
        app.logger.error("Returning error to the microservice")
        return jsonify(error="No json parameter"), 401
    else:
        app.logger.info(f"json = {json}")

    try:

        if json["service"] not in ["storage", "compute"]:
            app.logger.error(f"Service parameter {json['service']} not valid")
            return jsonify(error=f"Service parameter {json['service']} not valid"), 401

        _tasks = persistence.get_service_tasks(r, json["service"], json["status_code"])

    except KeyError as e:
        app.logger.error(f"Key {e.args} in 'json' parameter is missing")
        return jsonify(error=f"{e.args} parameter missing"), 401

    if _tasks == None:
        return jsonify(error=f"Persistence server task retrieve error for service {json['service']}"), 404

    # return only the tasks that matches with the required status in json["status_code"] list
    return jsonify(tasks=_tasks), 200

@app.before_request
def f_before_request():
    g.TID = request.headers.get(TRACER_HEADER, '')

@app.after_request
def after_request(response):
    # LogRequestFormatetter is used, this messages will get time, thread, etc
    logger.info('%s %s %s %s %s', request.remote_addr, request.method, request.scheme, request.full_path, response.status)
    return response


if __name__ == "__main__":
    if SSL_ENABLED:
        app.run(debug=DEBUG_MODE, host='0.0.0.0', use_reloader=False, port=TASKS_PORT, ssl_context=(SSL_CRT, SSL_KEY))
    else:
        app.run(debug=DEBUG_MODE, host='0.0.0.0', use_reloader=False, port=TASKS_PORT)
