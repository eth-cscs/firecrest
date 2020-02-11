#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from flask import Flask, request, jsonify
import paramiko
from logging.handlers import TimedRotatingFileHandler
import threading
import async_task
from cscs_api_common import check_header, get_username, get_buffer_lines, get_squeue_buffer_lines, \
    create_certificates, exec_remote_command, create_task, update_task, expire_task, clean_err_output

from job_time import check_sacctTime

import logging

from math import ceil

import socket

import json, urllib, tempfile, os
from werkzeug.utils import secure_filename

from datetime import datetime

import jwt

AUTH_HEADER_NAME = 'Authorization'

CERTIFICATOR_URL= os.environ.get("CERTIFICATOR_URL")
TASKS_URL       = os.environ.get("TASKS_URL")
STATUS_IP       = os.environ.get("STATUS_IP")
KONG_URL        = os.environ.get("KONG_URL")

COMPUTE_PORT    = os.environ.get("COMPUTE_PORT", 5000)


# SYSTEMS_PUBLIC: list of allowed systems
# remove quotes and split into array
SYSTEMS_PUBLIC  = os.environ.get("SYSTEMS_PUBLIC").strip('\'"').split(";")
# internal machines to submit/query jobs
SYS_INTERNALS   = os.environ.get("SYSTEMS_INTERNAL_COMPUTE").strip('\'"').split(";")

# base dir for sbatch files
JOB_BASE_DIR=os.environ.get("JOB_BASE_DIR").strip('\'"')

# scopes: get appropiate for jobs/storage, eg:  firecrest-tds.cscs.ch, firecrest-production.cscs.ch
FIRECREST_SERVICE = os.environ.get("FIRECREST_SERVICE", '').strip('\'"')

debug = os.environ.get("DEBUG_MODE", None)


app = Flask(__name__)


# Extract jobid number from SLURM sbatch returned string when it's OK
# Commonly  "Submitted batch job 9999" being 9999 a jobid
def extract_jobid(outline):

    try:
        # splitting string by spaces
        list_line = outline.split()
        # last element should be the jobid
        jobid = int(list_line[-1])

        return jobid

    except ValueError as e:
        app.logger.error("Wrong SLURM sbatch return string")
        app.logger.error("Couldn't convert to int")
        app.logger.error(e)


    except IndexError as e:
        app.logger.error("Wrong SLURM sbatch return string")
        app.logger.error("String is empty")
        app.logger.error(e)

    except Exception as e:
        app.logger.error("Wrong SLURM sbatch return string")
        app.logger.error("Generic error")
        app.logger.error(e)

    # for compatibility reasons if error, returns original string
    return outline



# function to check if pattern is in string
def in_str(stringval,words):
    try:
        stringval.index(words)
        return True
    except ValueError:
        return False


# copies file and submits with sbatch
def paramiko_scp(auth_header, cluster, sourcePath, targetPath):

    # no need to check auth_token, it was delivered by another entry point

    # get certificate
    cert_list = create_certificates(auth_header, cluster)

    if cert_list == None:
        result = {"error": 1, "msg": "Cannot create certificates"}
        return result

    [pub_cert, pub_key, priv_key, temp_dir] = cert_list

    # decode username from auth_header
    username = get_username(auth_header)

    try:
        # get scopes from token
        decoded = jwt.decode(auth_header[7:], verify=False)
        # scope: "openid profile email firecrest-tds.cscs.ch/storage/something"
        scopes = decoded['scope'].split(' ')
        scopes_parameters = ''

        # SCOPES sintax: id_service/microservice/parameter
        for s in scopes:
            s2 = s.split('/')
            if s2[0] == FIRECREST_SERVICE:
                if s2[1] == 'storage':
                    if scopes_parameters != '':
                        scopes_parameters = scopes_parameters + ','

                    scopes_parameters = scopes_parameters + s2[2]

        if scopes_parameters != '':
            scopes_parameters = '--firecrest=' + scopes_parameters

        app.logger.info("scope parameters: " + scopes_parameters)

    except Exception as e:
        app.logger.error(type(e))

        app.logger.error(e)
        errmsg = e
        result = {"error":1, "msg":errmsg}


    # -------------------
    # remote exec with paramiko
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ipaddr = cluster.split(':')
        host = ipaddr[0]
        if len(ipaddr) == 1:
            port = 22
        else:
            port = int(ipaddr[1])

        client.connect(hostname=host, port=port,
                       username=username,
                       key_filename="{pub_cert}".format(pub_cert=pub_cert),
                       allow_agent=False,
                       look_for_keys=False,
                       timeout=10)

        # create tmpdir for sbatch file
        action="mkdir -p {tmpdir}".format(tmpdir=targetPath)
        app.logger.info(action)

        stdin, stdout, stderr = client.exec_command(action)

        # replace stderr for errda which is more informative
        errno = stderr.channel.recv_exit_status()
        errda = clean_err_output(stderr.channel.recv_stderr(1024))

        outlines = get_buffer_lines(stdout)

        if outlines:
            app.logger.info("(No errors) --> {stdout}".format(errno=errno, stdout=outlines))

        if errno > 0 or len(errda) > 0:
            app.logger.error("(Error {errno}) --> {stderr}".format(errno=errno, stderr=errda))
            result = {"error": 1, "msg": errda}
            return result
        ## end create tmpdir

        # write sbatch file
        sourceFile = open(sourcePath,"r")

        action = "cat > {targetPath}/{sourcePath}".format(targetPath=targetPath,sourcePath=sourcePath)

        stdin, stdout, stderr = client.exec_command(action)

        for _line in sourceFile:
            stdin.channel.send(_line)

        stdin.channel.shutdown_write()
        sourceFile.close()
        # END: write sbatch file


        # execute sbatch
        action = "cd {target_path}; sbatch {scopes} {sbatch_file}".format(target_path=targetPath,
                                                              sbatch_file=sourcePath, scopes=scopes_parameters)

        app.logger.info(action)

        stdin, stdout, stderr = client.exec_command(action)
        errno = stderr.channel.recv_exit_status()
        #getting error:
        errda = clean_err_output(stderr.channel.recv_stderr(1024))

        outlines = get_buffer_lines(stdout)

        if outlines:
            app.logger.info("(No error) --> {stdout}".format(errno=errno, stdout=outlines))

        if errno > 0 or len(errda) > 0:
            app.logger.error("(Error {errno}) --> {stderr}".format(errno=errno, stderr=errda))
            result = {"error": 1, "msg": errda}
        else:
            # if there's no error JobID should be extracted from slurm output
            # standard output is "Submitted batch job 9999" beign 9999 a jobid
            # it would be treated in extract_jobid function

            jobid = extract_jobid(outlines)

            msg = {"result":"Job submitted", "jobid":jobid}

            result = {"error": 0, "msg": msg}

    # first if paramiko exception raise
    except paramiko.ssh_exception.NoValidConnectionsError as e:
        app.logger.error(type(e))
        if e.errors:
            for k,v in e.errors.items():
                app.logger.error("errorno: {errno}".format(errno=v.errno))
                app.logger.error("strerr: {strerr}".format(strerr=v.strerror))
                result = {"error": v.errno, "msg": v.strerror}

    except socket.gaierror as e:
        app.logger.error(type(e))
        app.logger.error(e.errno)
        app.logger.error(e.strerror)

        result = {"error": e.errno, "msg":e}

    # second: time out
    except socket.timeout as e:
        app.logger.error(type(e))
        # timeout has not errno
        app.logger.error(e)
        result = {"error": 1, "msg": e}

    except IOError as e:
        app.logger.error(e.filename)
        app.logger.error(e.strerror)
        result = {"error": 1, "msg": e.message}

    except Exception as e:
        app.logger.error(type(e))

        app.logger.error(e)
        errmsg = e

        result = {"error":1, "msg":errmsg}

    finally:
        client.close()


    os.remove(pub_cert)
    os.remove(pub_key)
    os.remove(priv_key)
    os.rmdir(temp_dir)

    return result


# returns temp dir, now obsolete
def get_temp_dir():
    # format obtained: YYYY-MM-DDTHH:mm:ss.uuuuuu
    time_str = str(datetime.now().isoformat())
    time_str = time_str.replace('.', '-')
    timestamp = time_str.replace(':', '-')

    return "cscs-api-sbatch-{timestamp}".format(timestamp=timestamp)



def submit_job_task(auth_header,machine,fileName,tmpdir,task_id):
    # auth_header doesn't need to be checked,
    # it's delivered by another instance of Jobs,
    # and this function is not an entry point

    resp = paramiko_scp(auth_header, machine, fileName, "{job_base_dir}/firecrest/{tmpdir}"
                        .format(job_base_dir=JOB_BASE_DIR, tmpdir=tmpdir))

    # in case of error:
    if resp["error"] == -2:
        update_task(task_id, auth_header, async_task.ERROR, "Machine is not available")
        return

    if resp["error"] == 1:
        update_task(task_id, auth_header, async_task.ERROR, resp["msg"])
        return

    # if job was submited succesfully, then "msg" is a dictionary with jobid field
    update_task(task_id, auth_header, async_task.SUCCESS, resp["msg"],True)


# Submit a batch script to SLURM on the target system.
# The batch script is uploaded as a file
@app.route("/jobs",methods=["POST"])
def submit_job():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Failed to submit job",error="Wrong auth"), 401

    try:
        machine = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machine not in SYSTEMS_PUBLIC:
        header={"X-Machine-Does-Not-Exists":"Machine does not exists"}
        return jsonify(description="Failed to submit job file",error="Machine does not exists"), 400, header

    # iterate over SYSTEMS_PUBLIC list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machine:
            machine = SYS_INTERNALS[i]
            break

    try:
        # check if the post request has the file part
        if 'file' not in request.files:
            app.logger.error('No batch file part')
            error = jsonify(description="Failed to submit job file", error='No batch file part')
            return error, 400

        file = request.files['file']

        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            app.logger.error('No batch file selected')
            error = jsonify(description="Failed to submit job file", error='No batch file selected')
            return error, 400

        # save file locally (then removed)
        file.save(secure_filename(file.filename))

    except Exception as e:
        data = jsonify(description="Failed to submit job file",error=e)
        return data, 400


    task_id = create_task(auth_header,service="compute")
    # if error in creating task:
    if task_id == -1:
        return jsonify(description="Failed to submit job file",error='Error creating task'), 400

    # scp file.filename .
    # create tmp file with timestamp
    # tmpdir = get_temp_dir()
    # now using hash_id from Tasks, which is user-task_id (internal)
    tmpdir = "{task_id}".format(task_id=task_id)

    try:
        # asynchronous task creation
        aTask = threading.Thread(target=submit_job_task,
                             args=(auth_header, machine, file.filename, tmpdir, task_id))

        aTask.start()
        retval = update_task(task_id, auth_header, async_task.QUEUED, TASKS_URL)

        task_url = "{KONG_URL}/tasks/{task_id}".format(KONG_URL=KONG_URL, task_id=task_id)
        data = jsonify(success="Task created", task_id=task_id, task_url=task_url)
        return data, 201

    except Exception as e:
        data = jsonify(description="Failed to submit job",error=e)
        return data, 400



# Retrieves information from all jobs (squeue)
@app.route("/jobs",methods=["GET"])
def list_jobs():

    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401


    if not check_header(auth_header):
        return jsonify(description="Failed to retrieve jobs information",error="Wrong auth"), 401

    try:
        machine = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machine not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Failed to retrieve jobs information", error="Machine does not exists"), 400, header

    # iterate over SYSTEMS_PUBLIC list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machine:
            machine = SYS_INTERNALS[i]
            break

    username = get_username(auth_header)

    app.logger.info("Getting SLURM information of jobs from {machine}".
                    format(machine=machine))

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
    job_list = ""
    if jobs != None:
        try:
            # check if input is correct:
            job_aux_list = jobs.split(",")
            if '' in job_aux_list:
                return jsonify(error="Jobs list wrong format",description="Failed to retrieve job information"), 400

            job_list="--job={jobs}".format(jobs=jobs)
        except:
            return jsonify(error="Jobs list wrong format",description="Failed to retrieve job information"), 400

    # format: jobid (i) partition (P) jobname (j) user (u) job sTate (T),
    #          start time (S), job time (M), left time (L)
    #           nodes allocated (M) and resources (R)
    action = "squeue -u {username} {job_list} --format='%i|%P|%j|%u|%T|%M|%S|%L|%D|%R' --noheader".\
        format(username=username, job_list=job_list)

    try:
        task_id = create_task(auth_header,service="compute")
        update_task(task_id, auth_header, async_task.QUEUED)

        # asynchronous task creation
        aTask = threading.Thread(target=list_job_task,
                                 args=(auth_header, machine, action, task_id, pageSize, pageNumber))

        aTask.start()

        task_url = "{KONG_URL}/tasks/{task_id}".format(KONG_URL=KONG_URL, task_id=task_id)

        data = jsonify(success="Task created", task_id=task_id, task_url=task_url)
        return data, 200

    except Exception as e:
        data = jsonify(description="Failed to retrieve job information",error=e)
        return data, 400



def list_job_task(auth_header,machine,action,task_id,pageSize,pageNumber):
    # exec command
    resp = exec_remote_command(auth_header, machine, action)

    app.logger.info(resp)

    # in case of error:
    if resp["error"] == -2:
        update_task(task_id, auth_header, async_task.ERROR,"Machine is not available")
        return

    if resp["error"] == 1:
        update_task(task_id, auth_header, async_task.ERROR ,resp["msg"])
        return

    if len(resp["msg"]) == 0:
         #update_task(task_id, auth_header, async_task.SUCCESS, "You don't have active jobs on {machine}".format(machine=machine))
         update_task(task_id, auth_header, async_task.SUCCESS,{},True)
         return

    # on success:
    jobList = resp["msg"].split("$")
    app.logger.info("Size jobs: %d" % len(jobList))

    # pagination
    totalSize   = len(jobList)
    pageNumber  = float(pageNumber)
    pageSize    = float(pageSize)

    totalPages = int(ceil(float(totalSize) / float(pageSize)))

    app.logger.info("Total Size: {totalSize}".format(totalSize=totalSize))
    app.logger.info("Total Pages: {totalPages}".format(totalPages=totalPages))

    if pageNumber < 0 or pageNumber > totalPages-1:
        app.logger.warning(
            "pageNumber ({pageNumber}) greater than total pages ({totalPages})".format(pageNumber=pageNumber,
                                                                                       totalPages=totalPages))
        app.logger.warning("set to default")
        pageNumber = 0

    beg_reg = int(pageNumber * pageSize)
    end_reg = int( (pageNumber+1 * pageSize) -1 )

    app.logger.info("Initial reg {beg_reg}, final reg: {end_reg}".format(beg_reg=beg_reg, end_reg=end_reg))

    jobList = jobList[beg_reg:end_reg + 1]

    jobs = {}
    for job_index in range(len(jobList)):

        job = jobList[job_index]

        jobaux = job.split("|")
        jobinfo = {"jobid": jobaux[0], "partition": jobaux[1], "name": jobaux[2],
                   "user": jobaux[3], "state": jobaux[4], "start_time": jobaux[5],
                   "time": jobaux[6], "time_left": jobaux[7],
                   "nodes": jobaux[8], "nodelist": jobaux[9]}

        jobs[str(job_index)]=jobinfo

    data = jobs

    update_task(task_id, auth_header, async_task.SUCCESS, data, True)

    # set expiration:
    expire_task(task_id, auth_header)




# Retrieves information from a jobid
@app.route("/jobs/<jobid>",methods=["GET"])
def list_job(jobid):
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Failed to retrieve job information",error="Wrong auth"), 401

    try:
        machine = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machine not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Failed to retrieve job information", error="Machine does not exists"), 400, header

    # iterate over SYSTEMS_PUBLIC list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machine:
            machine = SYS_INTERNALS[i]
            break

    username = get_username(auth_header)
    app.logger.info("Getting SLURM information of job={jobid} from {machine}".
                    format(machine=machine,jobid=jobid))

    # format: jobid (i) partition (P) jobname (j) user (u) job sTate (T),
    #          start time (S), job time (M), left time (L)
    #           nodes allocated (M) and resources (R)
    action = "squeue -u {username} --format='%i|%P|%j|%u|%T|%M|%S|%L|%D|%R' --noheader -j {jobid}".\
        format(username=username,jobid=jobid)

    try:
        # obtain new task from Tasks microservice
        task_id = create_task(auth_header,service="compute")
        update_task(task_id, auth_header, async_task.QUEUED)

        # asynchronous task creation
        aTask = threading.Thread(target=list_job_task,
                                 args=(auth_header, machine, action, task_id, 1, 1))

        aTask.start()

        task_url = "{KONG_URL}/tasks/{task_id}".format(KONG_URL=KONG_URL, task_id=task_id)

        data = jsonify(success="Task created", task_id=task_id, task_url=task_url)
        return data, 200

    except Exception as e:
        data = jsonify(description="Failed to retrieve job information",error=e)
        return data, 400



def cancel_job_task(auth_header,machine,action,task_id):
    # exec scancel command
    resp = exec_remote_command(auth_header, machine, action)

    data = resp["msg"]

    # in case of error:
    # permission denied, jobid to be canceled is owned by user without permission
    if resp["error"] == 210:
        update_task(task_id,auth_header, async_task.ERROR, "User does not have permission to cancel job")
        return

    if resp["error"] == -2:
        update_task(task_id,auth_header, async_task.ERROR, "Machine is not available")
        return

    # in specific scancel's case, this command doesn't give error code over
    # invalid or completed jobs, but -v catches stderr even if it's ok
    # so, if error key word is on stderr scancel has failed, otherwise:

    # if "error" word appears:
    if in_str(data,"error"):
        update_task(task_id, auth_header, async_task.ERROR, data)
        return

    # otherwise
    update_task(task_id,auth_header,async_task.SUCCESS,data)





# Cancel job from SLURM using scancel command
@app.route("/jobs/<jobid>",methods=["DELETE"])
def cancel_job(jobid):
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Failed to delete job",error="Wrong auth"), 401

    try:
        machine = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machine not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Failed to delete job", error="Machine does not exists"), 400, header

    # iterate over SYSTEMS_PUBLIC list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machine:
            machine = SYS_INTERNALS[i]
            break


    app.logger.info("Cancel SLURM job={jobid} from {machine}".
                    format(machine=machine, jobid=jobid))

    # scancel with verbose in order to show correctly the error
    action = "scancel -v {jobid}".format(jobid=jobid)

    try:
        # obtain new task from TASKS microservice
        task_id = create_task(auth_header,service="compute")

        # asynchronous task creation
        aTask = threading.Thread(target=cancel_job_task,
                             args=(auth_header, machine, action, task_id))

        aTask.start()

        update_task(task_id, auth_header, async_task.QUEUED)

        task_url = "{KONG_URL}/tasks/{task_id}".format(KONG_URL=KONG_URL, task_id=task_id)

        data = jsonify(success="Task created", task_id=task_id, task_url=task_url)
        return data, 200

    except Exception as e:
        data = jsonify(description="Failed to delete job",error=e)
        return data, 400


def acct_task(auth_header, machine, action, task_id):
    # exec remote command
    resp = exec_remote_command(auth_header, machine, action)

    app.logger.info(resp)

    data = resp["msg"]

    # in case of error:
    if resp["error"] == -2:
        update_task(task_id,auth_header, async_task.ERROR, "Machine is not available")
        return

    # in case of error:
    if resp["error"] == 1:
        update_task(task_id,auth_header,async_task.ERROR, data)
        return

    if len(resp["msg"]) == 0:
        update_task(task_id,auth_header, async_task.SUCCESS, {},True)
        return

    # on success:
    joblist = resp["msg"].split("$")
    jobs = []
    for job in joblist:

        jobaux = job.split("|")
        jobinfo = {"jobid": jobaux[0], "partition": jobaux[1], "name": jobaux[2],
                   "user": jobaux[3], "state": jobaux[4], "start_time": jobaux[5],
                   "time": jobaux[6], "time_left": jobaux[7],
                   "nodes": jobaux[8], "nodelist": jobaux[9]}

        jobs.append(jobinfo)

    # as it is a json data to be stored in Tasks, the is_json=True
    update_task(task_id, auth_header, async_task.SUCCESS, jobs, is_json=True)

    # set expiration:
    expire_task(task_id, auth_header)


# Job account information
@app.route("/acct",methods=["GET"])
def acct():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401


    if not check_header(auth_header):
        return jsonify(description="Failed to retrieve account information",error="Wrong auth"), 401

    try:
        machine = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machine not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Failed to retrieve account information", error="Machine does not exists"), 400, header

    # iterate over SYSTEMS_PUBLIC list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machine:
            machine = SYS_INTERNALS[i]
            break

    #check if startime (--startime=) param is set:
    start_time_opt = ""

    try:
        starttime = request.args.get("starttime","")
        if starttime != "":
            # check if starttime parameter is correctly encoded
            if check_sacctTime(starttime):
                start_time_opt  = " --starttime={start_time} ".format(start_time=starttime)
            else:
                app.logger.warning("starttime wrongly encoded")

        # check if endtime (--endtime=) param is set:
        end_time_opt = ""
        endtime   =  request.args.get("endtime","")
        if endtime != "":
            # check if endtime parameter is correctly encoded
            if check_sacctTime(endtime):
                end_time_opt = " --endtime={end_time} ".format(end_time=endtime)
            else:
                app.logger.warning("endtime wrongly encoded")
    except Exception as e:
        data = jsonify(description="Failed to retrieve account information", error=e)
        return data, 400


    # sacct
    # -X so no step information is shown (ie: just jobname, not jobname.batch or jobname.0, etc)
    # --starttime={start_time_opt} starts accounting info
    # --endtime={start_time_opt} end accounting info
    # format: 0 - jobid  1-partition 2-jobname 3-user 4-job sTate,
    #         5 - start time, 6-elapsed time , 7-end time
    #          8 - nodes allocated and 9 - resources
    # --parsable2 = limits with | character not ending with it

    action = "sacct -X {starttime} {endtime} " \
             "--format='jobid,partition,jobname,user,state,start,cputime,end,NNodes,NodeList' " \
              "--noheader --parsable2".format(starttime=start_time_opt,endtime=end_time_opt)

    try:
        # obtain new task from Tasks microservice
        task_id = create_task(auth_header,service="compute")

        update_task(task_id, auth_header, async_task.QUEUED)

        # asynchronous task creation
        aTask = threading.Thread(target=acct_task,
                                 args=(auth_header, machine, action, task_id))

        aTask.start()
        task_url = "{KONG_URL}/tasks/{task_id}".format(KONG_URL=KONG_URL, task_id=task_id)

        data = jsonify(success="Task created", task_id=task_id, task_url=task_url)
        return data, 200

    except Exception as e:
        data = jsonify(description="Failed to retrieve account information",error=e)
        return data, 400

# get status for status microservice
# only used by STATUS_IP otherwise forbidden
@app.route("/status",methods=["GET"])
def status():

    app.logger.info("Test status of service")

    if request.remote_addr != STATUS_IP:
        app.logger.warning("Invalid remote address: {addr}".format(addr=request.remote_addr))
        return jsonify(error="Invalid access"), 403

    return jsonify(success="ack"), 200


if __name__ == "__main__":
    # log handler definition
    # timed rotation: 1 (interval) rotation per day (when="D")
    logHandler = TimedRotatingFileHandler('/var/log/compute.log', when='D', interval=1)

    logFormatter = logging.Formatter('%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                                     '%Y-%m-%d:%H:%M:%S')
    logHandler.setFormatter(logFormatter)
    logHandler.setLevel(logging.DEBUG)

    # get app log (Flask+werkzeug+python)
    logger = logging.getLogger()
    # logger = app.logger

    # set handler to logger
    logger.addHandler(logHandler)

    # set debug = False, so output goes to log files
    app.run(debug=debug, host='0.0.0.0', port=COMPUTE_PORT)
