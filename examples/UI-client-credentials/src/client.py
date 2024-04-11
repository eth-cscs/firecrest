import tempfile
import os
import threading
from typing import Union

from flask import (Flask, g, render_template, request, jsonify, session)
from flask_socketio import SocketIO, emit
from flask_session import Session

from flask_bootstrap import Bootstrap5
from werkzeug.utils import secure_filename
from flask_sslify import SSLify

import jinja2

import logging
from logging.handlers import TimedRotatingFileHandler

import firecrest as f7t

from config import DevConfig



def create_app():
    app = Flask(__name__)
    app.config.from_object(DevConfig)

    Session(app)

    # to have continue, break statements in jinja
    app.jinja_env.add_extension('jinja2.ext.loopcontrols')

    return app


app = create_app()
async_mode = "threading"
socketio = SocketIO(app, async_mode=async_mode)

sslify = SSLify(app) # SSL support
bootstrap = Bootstrap5(app) # bootstrap support

try:

    FIRECREST_URL = app.config["FIRECREST_URL"]
    DEBUG = app.config["DEBUG"]
    OIDC_CLIENT_ID = app.config["OIDC_CLIENT_ID"]
    OIDC_CLIENT_SECRET = app.config["OIDC_CLIENT_SECRET"]
    OIDC_AUTH_REALM = app.config["OIDC_AUTH_REALM"]
    OIDC_AUTH_BASE_URL = app.config["OIDC_AUTH_BASE_URL"]

    OIDC_AUTH_WEB_ISSUER_URL = f"{OIDC_AUTH_BASE_URL}/auth/realms/{OIDC_AUTH_REALM}"
    OIDC_AUTH_TOKEN_URL = f"{OIDC_AUTH_WEB_ISSUER_URL}/protocol/openid-connect/token"

    SYSTEM_NAME = app.config["SYSTEM_NAME"]
    SYSTEM_PARTITIONS = app.config["SYSTEM_PARTITIONS"]
    SYSTEM_CONSTRAINTS = app.config["SYSTEM_CONSTRAINTS"]
    SYSTEM_RESERVATION = app.config["SYSTEM_RESERVATION"]
    USER_GROUP = app.config["USER_GROUP"]


    PROBLEM_SUBDIR = app.config["PROBLEM_SUBDIR"]
    PROBLEM_INI_FILE = app.config["PROBLEM_INI_FILE"]
    PROBLEM_MSH_FILE = app.config["PROBLEM_MSH_FILE"]
    SBATCH_TEMPLATE = app.config["SBATCH_TEMPLATE"]
    POST_TEMPLATE = app.config["POST_TEMPLATE"]

except KeyError as ke:
    app.logger.error(f"Error in configuration file: {ke}")


# global variables
JOB_LIST = {}
JOB_DIR = None
POST_JOB_ID = None
SYSTEM_BASE_DIR = None

authN = f7t.ClientCredentialsAuth(OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_AUTH_TOKEN_URL)

f7t_client = f7t.Firecrest(
    firecrest_url=FIRECREST_URL, authorization=authN
)

def is_system_avail_f7t(system_name: str) -> bool:
    '''
        - Name: `is_system_avail_f7t`
        - Description:
           This function should return `True` if the `system_name` is available, otherwise `False`
        - Params:
          - `system_name`: str          
        - Returns:
          - `bool`
    '''

    try:
        system =  f7t_client.system(system_name)

        if system["status"] == "available":
            return True

        return False

    except f7t.FirecrestException as fe:
        app.logger.debug(f"Error getting username: {fe} ")
        return False
    

def list_files_with_f7t(system_name: str, target_path: str) -> list:
    '''
        - Name: `list_files_dir`
        - Description:
           This function should return a list of files on `target_path` on the `system_name`.
            In case of error, it should return None
        - Params:
          - `system_name`: str
          - `target_path`: str
        - Returns:
          - `list` | `None`
    '''

    try:
        return f7t_client.list_files(system_name,target_path)
    except f7t.FirecrestException as fe:
        app.logger.debug(f"Error listing files in directory {target_path}: {fe} ")
        return None



def get_username_with_f7t(system_name):
    '''
        - Name: `get_username_with_f7t`
        - Description:
        This function should return the username of the current OIDC credential owner
        Returns None if the username is not found
        - Params:
          - `system_name`: str
        - Returns:
          - str|None
    '''

    try:
        return f7t_client.whoami(system_name)
    except f7t.FirecrestException as fe:
        app.logger.debug(f"Error getting username: {fe} ")
        return None

def get_base_fs_with_f7t(system_name: str) -> str:
    '''
        - Name: `get_avail_fs_with_f7t`
        - Description This function should return a python dictionary of
        `{"system_name":"system_base_dir" }` being `system_base_dir` the `mounted` filesystem for the `system_name`
        - Params:
          - `system_name: str`
        - Returns:
          - `None`
    '''
    
    try:
        storage_params =  f7t_client.parameters()["storage"]

        for st_param in storage_params:
            if st_param["name"] == "FILESYSTEMS":
                fs_values = st_param["value"]
                for value in fs_values:
                    if value["system"] == system_name:
                        if DEBUG:
                            app.logger.debug(f"Base FS found in {system_name}: {value['mounted'][0]}")
                        return value["mounted"][0]

    except f7t.FirecrestException as fe:
        app.logger.debug(f"Error getting username: {fe} ")
        return None
    
    return None


def submit_job_with_f7t(system_name: str, job_script: str) -> dict:

    '''
        - Name: `submit_job_with_f7t`
        - Description: submit a job in a given `system_name` for a given sbatch path in `job_script`
          - If the job was submitted correctly should return a dictionary : `{"job": firecrest.types.JobSubmit, "error": 0}`
          - If the job couldn't be submitted should return a dictionary : `{"job": "error description", "error": 1}`
        - Params:
          - `system_name`: str
          - `job_script` : str

        - Returns:
          - `dict`

    '''

    try:
        job = f7t_client.submit(system_name, job_script)

        return {"job": job, "error": 0}
    except f7t.FirecrestException as fe:
        app.logger.debug(f"Error submitting job: {fe} ")
        return {"job": f"Error submitting job: {fe} ", "error": 1}



def mkdir_with_f7t(system_name: str, target_path: str) -> bool:

    '''
    - Name: mkdir_with_f7t
    - Description: creates a directory using FirecREST. Returns `True` if the directory was created, or `False` otherwise
      If the parent directory doesn't exist, it has to be created.
    - Params:
      - `system_name`: str
      - `target_path`
    - Returns:
      - `bool`

    '''

    try:
        f7t_client.mkdir(system_name, target_path, p=True)
        return True
    except f7t.FirecrestException as fe:
        app.logger.debug(f"Error creating directory {target_path}: {fe} ")
        return False
    
def list_jobs_with_f7t(system_name: str, job_ids: list[int]) -> dict:
    '''
    - Name: list_jobs_with_f7t
    - Description: list queued and passed (completed, cancelled, pending, etc) 
    in a specific `system_name` and filtered by a specific list of job IDs (`job_ids`)

    If the job_ids list is empty return {"jobs":[], "error": 0}, 
    otherwise a list of `firecrest.types.JobQueue`
      
    - Parameters:
      - `system_name`: str
      - `job_ids`: list[int]

    - Returns
      - dict: {"jobs": Union[firecrest.types.JobQueue | list [] ], "error": int}
    '''

    if len(job_ids) == 0:
        return {"jobs": [], "error": 0}
    
    try:

        jobs = f7t_client.poll(system_name,jobs=job_ids)

        if len(jobs) == 0:
            return {"jobs": [] , "error":0}
        
        if DEBUG:
            for job in jobs:
                app.logger.debug(job)

        return {"jobs": jobs, "error":0}

    except f7t.FirecrestException as fe:
        app.logger.error(f"Error listing jobs: {fe}")
        
        return {"jobs": [], "error": 1}

        
    



def mkdir(jobName):

    username = get_username_with_f7t(SYSTEM_NAME)
    if username == None:
        return {"error": 1, "msg":f"Error creating directory: couldn't get username"}

    targetPath = f"{SYSTEM_BASE_DIR}/{username}/{PROBLEM_SUBDIR}/{jobName}"
    if DEBUG:
        app.logger.debug(f"targetPath: {targetPath}")

    if mkdir_with_f7t(SYSTEM_NAME,targetPath):
        return {"error": 0, "msg": f"Directory {targetPath} created"}

    return {"error": 1, "msg":f"Error creating directory {targetPath}"}


@app.route("/list_files", methods=["GET"])
def list_files():

    targetPath = request.args.get('path',None)

    if targetPath == None:
        return jsonify(rows=[]), 400

    files = list_files_with_f7t(SYSTEM_NAME, targetPath)

    if files == None:
        return jsonify(rows=[]), 400

    return jsonify(rows=files), 200

@app.route("/list_jobs", methods=["GET"])
def list_jobs():

    global JOB_LIST

    if DEBUG:
        app.logger.debug(f"Job list to query: {list(JOB_LIST.keys())}")

    f7t_jobs = list_jobs_with_f7t(SYSTEM_NAME, list(JOB_LIST.keys()))

    if f7t_jobs["error"] == 0:
        return {"rows": f7t_jobs["jobs"]}
    

    return jsonify(response="Error listing jobs"), 400


@app.route("/results", methods=["GET"])
def results():

    global POST_JOB_ID

    try:

        resultImage = f"{session['jobDir']}/imag.gif"
        targetPath=f"/app/src/static/{POST_JOB_ID}.gif"
        imgPath = f"/static/{POST_JOB_ID}.gif"

        if DEBUG:
            app.logger.debug(f"source_path: {resultImage}")
            app.logger.debug(f"target_path: {targetPath}")

        dwn = f7t_client.simple_download(machine=SYSTEM_NAME,
                                         source_path=resultImage,
                                         target_path=targetPath)

        return jsonify(data=imgPath), 200

    except f7t.FirecrestException as fe:
        app.logger.error(f"Download error {fe}")
        return jsonify(data=f"Download error {fe}"), 400

    except Exception as e:
        if DEBUG:
            app.logger.error(f"Download error: {e}")

        return jsonify(data=f"Download error: {e}"), 400


def write_sbatch(jobTemplate, jobName="f7t_test", ntasks=1, account=None, partition=None,
                constraint=None,reservation=None,jobDir=None, problem_ini_file=None, problem_msh_file=None,step=1,lastJobId=None):

    try:
        # sbatch templates directory
        basePath = os.path.abspath(os.path.dirname(__file__))
        templatesPath = f"{basePath}/sbatch_templates/"

        if DEBUG:
            app.logger.debug(f"Sbatch Template: {templatesPath} / {jobTemplate}")

        # create environment
        jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(templatesPath))

        jinja_template = jinja_env.get_template(jobTemplate)

    except jinja2.exceptions.TemplateNotFound as tnf:
        if DEBUG:
            app.logger.error(f"Template {jobTemplate} not found")
            app.logger.error(f"Error: {tnf}")
        return {"error": 1, "msg":"Couldn't create sbatch file"}
    except Exception as e:
        if DEBUG:
            app.logger.error(f"Template {jobTemplate} not found")
            app.logger.error(f"Error: {e}")
        return {"error": 1, "msg":"Couldn't create sbatch file"}


    try:
        # creating temp sbatch file in client to upload in SYSTEM_NAME
        td = tempfile.mkdtemp(prefix="job")

        sbatch_file_path = f"{td}/sbatch-job.sh"

        if DEBUG:
            app.logger.info(f"Creating file: {sbatch_file_path}")

        with open(sbatch_file_path, "w") as sf:
            # replace templates variables with values
            sf.write(jinja_template.render(jobName=jobName, partition=partition, account=account,
                                     constraint=constraint, reservation=reservation, lastJobId=lastJobId, ntasks=ntasks, step=step, 
                                     jobDir=jobDir, problem_ini_file=problem_ini_file, problem_msh_file=problem_msh_file))

        if DEBUG:
            app.logger.info(f"Created file: {sbatch_file_path}")

    except IOError as ioe:
        if DEBUG:
            app.logger.debug(ioe.message)
        return {"error": 1, "msg":"Couldn't create sbatch file"}

    except Exception as e:
        if DEBUG:
            app.logger.error(e)
            app.logger.error(type(e))
        return {"error": 1, "msg":"Couldn't create sbatch file"}


    return {"error": 0, "path":sbatch_file_path}


def background_submit_postproc(jobTemplate,jobName,ntasks,partition,constraint,reservation,targetPath, 
                           problem_ini_file, problem_msh_file):
    
    global JOB_LIST
    global POST_JOB_ID
    
    try:

        # write sbatch file using the jobTemplate

        res = write_sbatch(jobTemplate=jobTemplate, jobName=f"{jobName}_post",ntasks=ntasks,account=USER_GROUP, partition=partition,
                constraint=constraint, reservation=reservation, jobDir=targetPath, problem_ini_file=problem_ini_file, problem_msh_file=problem_msh_file)
    except Exception as e:
        app.logger.error(e)

        socketio.emit("error", {"data":f"Error writing sbatch file for {jobName}_post ({e}"})
        # if the first step fails, then return the error to the frontend
        return {"data": f"Error writing sbatch file for {jobName}_post ({e}", "status": 400}
    
    # if the sbatch writing worked, then continue submitting jobs
    job_script = res["path"]
    job_submitted = submit_job_with_f7t(system_name=SYSTEM_NAME, job_script=job_script)

    if job_submitted["error"] == 1:

        socketio.emit("error", {"data":f"Error submitting job {jobName}_post ({job_submitted['job']}"})
        return {"data": f"Error submitting job {jobName}_post ({job_submitted['job']}", "status": 400}

    job = job_submitted["job"]

    socketio.emit("success", {"data":f"Job {jobName}_post submitted correctly (jobid: {job['jobid']})"})

    POST_JOB_ID = job["jobid"]
    JOB_LIST[job["jobid"]] = job_submitted["error"]

    if DEBUG:
        app.logger.debug(f"Job submission data: {job}")
    
    return {"data": "Postprocess job submitted correctly", "status": 200}


def background_submit_task(steps,jobTemplate,jobName,ntasks,partition,constraint,reservation,targetPath, 
                           problem_ini_file, problem_msh_file, isPostProcess):

    global JOB_LIST
    global POST_JOB_ID

    lastJobId = 0

    for step in range(1,steps+1):

        if step == 1:
            # if this is the first step, then enchained job is not needed

            try:

                # write sbatch file using the jobTemplate

                res = write_sbatch(jobTemplate=jobTemplate, jobName=f"{jobName}_{step}",ntasks=ntasks,account=USER_GROUP, partition=partition,
                        constraint=constraint, reservation=reservation, jobDir=targetPath, problem_ini_file=problem_ini_file, problem_msh_file=problem_msh_file, step=step)
            except Exception as e:
                app.logger.error(e)

                socketio.emit("error", {"data":f"Error writing sbatch file for {jobName}_{step} ({e}"})
                # if the first step fails, then return the error to the frontend
                return {"data": f"Error writing sbatch file for {jobName}_{step} ({e}", "status": 400}

        else:
            # step is not the first one
            try:
                res = write_sbatch(jobTemplate=jobTemplate,jobName=f"{jobName}_{step}", ntasks=1, account=USER_GROUP, partition=partition,
                            constraint=constraint, reservation=reservation, jobDir=targetPath, problem_ini_file=problem_ini_file, problem_msh_file=problem_msh_file, step=step,lastJobId=lastJobId )
            except Exception as e:
                app.logger.error(e)

                socketio.emit("error", {"data":f"Error writing sbatch file for {jobName}_{step} ({e}"})
                # if writing the next sbatch fails, then the whole process can't continue
                return {"data":f"Error writing sbatch file for {jobName}_{step} ({e}", "status": 400}

        if res["error"] == 1:

            socketio.emit("error", {"data":f"Error writing sbatch file for {jobName}_{step} ({res['msg']}"})
            return {"data":f"Error writing sbatch file for {jobName}_{step} ({res['msg']}", "status": 400}

        # if the sbatch writing worked, then continue submitting jobs
        job_script = res["path"]

        try:

            # so token is refreshed
            job_submitted = submit_job_with_f7t(system_name=SYSTEM_NAME, job_script=job_script)

            if job_submitted["error"] == 1:

                socketio.emit("error", {"data":f"Error submitting job {jobName}_{step} ({job_submitted['job']}"})
                return {"data": f"Error submitting job {jobName}_{step} ({job_submitted['job']}", "status": 400}

            job = job_submitted["job"]

            socketio.emit("success", {"data":f"Job {jobName}_{step} submitted correctly (jobid: {job['jobid']})"})

            if DEBUG:
                app.logger.debug(f"Job submission data: {job}")



            lastJobId = job["jobid"]
            data = job
            status = 200
            if step == 1 and not isPostProcess:
                # for the first job:
                #     session information and directory to the targetPath
                JOB_LIST = {}
            elif isPostProcess:
                POST_JOB_ID = lastJobId

            if DEBUG:
                app.logger.debug(f"Job list: {JOB_LIST}")

            # JOB_LIST global variable updated: JOB_LIST = {"<jobid>": "<error_boolean>""}

            JOB_LIST[job["jobid"]] = job_submitted["error"]

        except f7t.FirecrestException as fe:

            if DEBUG:
                app.logger.debug(f"Job submission error: {fe}")

            data = f"Job submission error: {fe}"
            status = 400

            return {"data": data, "status": status}

        except Exception as e:
            if DEBUG:
                app.logger.error(f"Job submission error: {e}")

            data = f"Job submission error: {e}"
            status = 400

            return {"data": data, "status": status}

    return {"data": "All jobs submitted correctly", "status": 200}


@app.route("/submit_job", methods=["POST"])
def submit_job():
    global SYSTEM_RESERVATION
    global PROBLEM_MSH_FILE
    global PROBLEM_INI_FILE

    reservation = None
    if SYSTEM_RESERVATION != '':
        reservation = SYSTEM_RESERVATION
    if DEBUG:
        app.logger.debug(f"Reservation to use: {reservation}")
    
    problem_ini_file = None
    if PROBLEM_INI_FILE != '':
        problem_ini_file = PROBLEM_INI_FILE        
    if DEBUG:
        app.logger.debug(f"Problem Ini File to use: {problem_ini_file}")

    problem_msh_file = None
    if PROBLEM_MSH_FILE != '':
        problem_msh_file = PROBLEM_MSH_FILE
    if DEBUG:
        app.logger.debug(f"Problem Ini File to use: {problem_msh_file}")

    try:
        ntasks = request.form["numberOfNodes"]
    except Exception as e:
        if DEBUG:
            app.logger.warning(e)
        ntasks = 1

    try:
        jobName = request.form["jobName"]
    except Exception as e:
        if DEBUG:
            app.logger.warning(e)
        jobName = "f7t_test"

    try:
        partition = request.form["partition"]
    except Exception as e:
        if DEBUG:
            app.logger.error(e)
        partition = None

    try:
        constraint = request.form["constraint"]
    except Exception as e:
        if DEBUG:
            app.logger.error(e)
        constraint = None

    try:
        steps = int(request.form["steps"])
    except Exception as e:
        if DEBUG:
            app.logger.error(e)
        steps = None

    try:
        isPostProcess = bool(request.form["isPostProcess"])
    except Exception as e:
        if DEBUG:
            app.logger.debug("Not a postprocess job")
        isPostProcess = False


    # created directory for the test in SYSTEM_BASE_DIR/username/PROBLEM_SUBDIR/jobName
    # ie: $SCRATCH/PyFr/examples/cylinder_inc/job_123456
    # if isPostProcess, then the directory /post is attached to JobName
    jobTemplate = SBATCH_TEMPLATE

    username = get_username_with_f7t(SYSTEM_NAME)
    if username == None:
        return jsonify(data=f"Error at getting username"), 400

    targetPath = f"{SYSTEM_BASE_DIR}/{username}/{PROBLEM_SUBDIR}/{jobName}"
    if DEBUG:
        app.logger.debug(f"targetPath: {targetPath}")

    # if it's a postprocess job, add "/post" to the name
    # and change template
    if isPostProcess:
        # jobName=f"{jobName}_post"
        jobTemplate = POST_TEMPLATE

    else:
        # if it is not a postprocess, a new directory should be created
        res_mkdir = mkdir(jobName=jobName)
        if res_mkdir["error"] != 0:
            return jsonify(data=res_mkdir["msg"]), 400


    if not isPostProcess:

        for pf_path in [problem_ini_file, problem_msh_file]:

            if pf_path == None:
                continue

            basePath = os.path.abspath(os.path.dirname(__file__))
            sourcePath = f"{basePath}/problem_files/{pf_path}"

            try:
                if DEBUG:
                    app.logger.debug(f"Uploading {sourcePath} to {targetPath}")

                upload_file = f7t_client.simple_upload(SYSTEM_NAME,source_path=sourcePath,target_path=targetPath)

            except f7t.FirecrestException as fe:
                app.logger.error(f"Error Uploading {sourcePath} to {targetPath}: {fe}")

                return jsonify(data="Error uploading initial data"), 400
    else:
        # if is postprocess, upload the post_proc.py file
        basePath = os.path.abspath(os.path.dirname(__file__))
        sourcePath = f"{basePath}/sbatch_templates/post_proc.py"

        try:
            
            app.logger.info(f"Checking if file {targetPath}/post_proc.py exists")

            files = f7t_client.list_files(SYSTEM_NAME,targetPath)

            found = False
            for f in files:
                if f["name"] == "post_proc.py":
                    app.logger.info("File found, skipping uploading")
                    found = True
                    break

            if not found:
                if DEBUG:
                    app.logger.debug("File not found, uploading")
                    app.logger.debug(f"Uploading {sourcePath} to {targetPath}")
            
                    upload_file = f7t_client.simple_upload(SYSTEM_NAME,source_path=sourcePath,target_path=targetPath)
            
            
        except f7t.FirecrestException as fe:
            app.logger.error(f"Error Uploading {sourcePath} to {targetPath}: {fe}")

            return jsonify(data="Error copying initial data"), 400

    if isPostProcess:
        bgtask = threading.Thread(target=background_submit_postproc,
                              args=(jobTemplate,jobName,ntasks,partition,constraint,reservation,targetPath,
                                    problem_ini_file, problem_msh_file))  
    else:
        bgtask = threading.Thread(target=background_submit_task,
                              args=(steps,jobTemplate,jobName,ntasks,partition,constraint,reservation,targetPath,
                                    problem_ini_file, problem_msh_file, isPostProcess))

    bgtask.start()
    session.clear()

    session["jobDir"] = targetPath
    session["jobName"] = jobName
    session["partition"] = partition
    session["constraint"] = constraint
    session["steps"] = steps
    session["numberOfNodes"] = ntasks
    session["activePost"] = isPostProcess

    if DEBUG:
        app.logger.debug("Information about job submission")
        app.logger.debug(f"jobDir: {session['jobDir']}")
        app.logger.debug(f"jobName: {session['jobName']}")

    return jsonify(data="Batch started"), 200


@app.before_request
def before_request():
    g.user = get_username_with_f7t(SYSTEM_NAME)
    app.logger.debug(g.user)


@app.route("/",methods=["GET","POST"])
def live():
    '''Function to live dashboard'''

    global SYSTEM_BASE_DIR

    system_status = "undefined"
    if is_system_avail_f7t(SYSTEM_NAME):
        system_status = "avail"
        SYSTEM_BASE_DIR = get_base_fs_with_f7t(SYSTEM_NAME)
    else:
        system_status="notavail"

    status = 200
    jobPath = f"{SYSTEM_BASE_DIR}/{g.user}/{PROBLEM_SUBDIR}/"

    data = {"partitions": SYSTEM_PARTITIONS, "constraints": SYSTEM_CONSTRAINTS, 
            "system": SYSTEM_NAME, "job_dir":jobPath, "system_status": system_status}

    if request.method == "POST":
        msg = None
        error = None

        try:
            msg = request.form["msg"]
            error = request.form["error"]
        except Exception as e:
            app.logger.warning(e)

        return render_template("live.html",  data=data, status=status, msg=msg, error=error)


    return render_template('live.html', data=data, status=status, error=0)




if __name__ == '__main__':
    logHandler = TimedRotatingFileHandler('/var/log/client.log', when='D', interval=1)

    logFormatter = logging.Formatter('%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                                     '%Y-%m-%d:%H:%M:%S')
    logHandler.setFormatter(logFormatter)
    logHandler.setLevel(logging.DEBUG)

    # get app log (Flask+werkzeug+python)
    logger = logging.getLogger()

    logger.addHandler(logHandler)

    USE_SSL = app.config['USE_SSL']

    CLIENT_PORT = app.config["CLIENT_PORT"]

    if not USE_SSL:
        socketio.run(app,host='0.0.0.0',port=CLIENT_PORT,allow_unsafe_werkzeug=True)
    else:
        SSL_PEM = app.config['SSL_PEM']
        SSL_KEY = app.config['SSL_KEY']
        socketio.run(app,host='0.0.0.0', ssl_context=(SSL_PEM, SSL_KEY), port=CLIENT_PORT)
