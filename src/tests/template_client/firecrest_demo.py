#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import json
import time
import requests
import tempfile
import datetime
import os

from io import BytesIO
from flask import (Flask, g, render_template, flash, redirect, url_for,
                   send_file, request, make_response, jsonify)
from flask_oidc import OpenIDConnect
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField, StringField, SelectField, IntegerField, RadioField, validators, TextAreaField, DateField
from wtforms.validators import InputRequired
from flask_wtf.file import FileRequired
from werkzeug.utils import secure_filename
from config import DevConfig
from flask_sslify import SSLify

import logging
from logging.handlers import TimedRotatingFileHandler

app = Flask(__name__)
app.config.from_object(DevConfig)
sslify = SSLify(app)

# to have continue, break statements in jinja
app.jinja_env.add_extension('jinja2.ext.loopcontrols')

bootstrap = Bootstrap(app)

demo_microservices = [ (m.title(),m) for m in app.config['MICROSERVICES'] ]

oidc = OpenIDConnect(app)

class MachineSelectForm(FlaskForm):
    '''A class to support selection of machine'''
    machine = SelectField('machine',
                          choices=[(m, m) for m in app.config['MACHINES']])
    submit = SubmitField('Submit')

class TestAPIForm(FlaskForm):
    machine = SelectField('machine',
                          choices=[(m, m) for m in app.config['MACHINES']])

    microservice = SelectField('microservice',
                          choices=[(value,name) for (name,value) in demo_microservices])

    query = StringField('query')

    method = SelectField('method', choices=[("DELETE","DELETE"), ("GET","GET"),
                            ("POST","POST"), ("PUT","PUT")])
    resp_headers = TextAreaField("Response Headers")
    # resp_json = TextAreaField("JSON Response")
    submit = SubmitField('Submit')


class UploadForm(FlaskForm):
    '''A class to support uploading of files'''
    filepath = StringField('destination', validators=[InputRequired()])
    upload = FileField('file', validators=[FileRequired()])
    machine = SelectField('machine',
                          choices=[(m, m) for m in app.config['MACHINES']])
    submit = SubmitField('Submit')


class JobForm(FlaskForm):
    '''A class to support uploading of sbatch files'''

    machine = SelectField('Machine',
                          choices=[(m, m) for m in app.config['MACHINES']])

    fileOrForm = RadioField("Select upload a file or fill form",choices=[("file","Upload a file"),("form","Fill the form")],default="file")

    upload = FileField('File', validators=[FileRequired()])
    constraint = SelectField('Constraint',choices=[("","None"),("gpu","GPU"),("mc","Multicore")],render_kw={"disabled":"disabled"})

    default_machine = app.config['MACHINES'][0]

    partition  = SelectField('Partition', choices=[(p,p) for p in app.config["PARTITIONS"][default_machine]], render_kw={"disabled":"disabled"})

    jobName = StringField("Job Name",render_kw={"disabled":"disabled"})
    nNodes = IntegerField("Number of nodes",validators=[validators.NumberRange(min=1,max=2400)],render_kw={"disabled":"disabled"},default=1)
    nTasksPerCore = IntegerField("Number of tasks per core",validators=[validators.NumberRange(min=1,max=2)],render_kw={"disabled":"disabled"},default=1)
    nTasksPerNode = IntegerField("Number of tasks per node",validators=[validators.NumberRange(min=1,max=36)],render_kw={"disabled":"disabled"},default=1)
    nCpusPerTask = IntegerField("Number of CPUs per task",validators=[validators.NumberRange(min=1,max=1)],render_kw={"disabled":"disabled"},default=1)

    email = StringField( "E-Mail address",render_kw={"disabled":"disabled"})
    command = TextAreaField("Command",render_kw={"disabled":"disabled"})

    submit = SubmitField('Submit')

class ListJobsForm(FlaskForm):
    '''A class to support uploading of files'''
    machine = SelectField('Machine',
                          choices=[(m, m) for m in app.config['MACHINES']])
    submit = SubmitField('Submit')

class ListAcctForm(FlaskForm):
    '''A class to support uploading of files'''
    machine = SelectField('Machine',
                          choices=[(m, m) for m in app.config['MACHINES']])
    today = datetime.date.today()
    starttime = DateField("From date", default=today)
    # set tomorrow for Slurm accounting, defaults to time=00:00:00
    endtime   = DateField("To date"  , default=(today + datetime.timedelta(days=1)))
    submit = SubmitField('Submit')

class SingleJobForm(FlaskForm):
    '''A class to support uploading of files'''
    machine = SelectField('machine',
                          choices=[(m, m) for m in app.config['MACHINES']])
    jobid = StringField("Job ID", validators=[InputRequired()])

    submit = SubmitField('Submit')

class CancelJobForm(FlaskForm):
    '''A class to support uploading of files'''
    machine = SelectField('Choose a machine',
                          choices=[(m, m) for m in app.config['MACHINES']])
    jobid = StringField("Job ID", validators=[InputRequired()])

    submit = SubmitField('Cancel')

class PathForm(FlaskForm):
    '''A class to support filepaths'''
    filepath = StringField('Enter the path', validators=[InputRequired()])
    machine = SelectField('machine',
                          choices=[(m, m) for m in app.config['MACHINES']])
    submit = SubmitField('Submit')


class XferCopyForm(FlaskForm):
    '''A class to support selection of machine'''
    sourcepath = StringField('Source', validators=[InputRequired()])
    destination_path = StringField('Destination', validators=[InputRequired()])
    job_name = StringField('Job Name', validators=[InputRequired()])
    time_limit = StringField('Time', default='02:00:00',
                             validators=[InputRequired()])
    submit = SubmitField('Submit')


class ApiForm(FlaskForm):
    '''A class to support raw api calls'''
    apipath = StringField('Enter the api call', validators=[InputRequired()])
    submit = SubmitField('Submit')


class ExternalUploadForm(FlaskForm):
    '''A class to support raw api calls'''
    targetPath = StringField('Enter the target path (directory)', default="{}/".format(app.config["HOME_DIR"]),
                             validators=[InputRequired()])
    sourcePath = FileField('Enter the source path',
                             validators=[InputRequired()])

    submit = SubmitField('Submit')



class StorageInternalForm(FlaskForm):
    '''A class to support raw api calls'''
    
    action = SelectField("Action",choices=[("cp","Copy"),("mv","Move/Rename"),("rm","Delete"),("rsync","Sync files")])

    targetPath = StringField('Enter the target path (directory)',
                             validators=[InputRequired()])
    sourcePath = StringField('Enter the source path',
                             validators=[InputRequired()])

    jobName = StringField("Enter job name (optional)")

    submit = SubmitField('Submit')


class ExternalDownloadForm(FlaskForm):
    '''A class to support raw api calls'''
    sourcePath = StringField('Enter the source path of the file in CSCS',
                             validators=[InputRequired()])
    submit = SubmitField('Submit')

class UploadFinishedForm(FlaskForm):
    '''A class to support raw api calls'''
    taskid = StringField("Task ID for the upload process")
    submit = SubmitField('Submit')


class SubmitForm(FlaskForm):
    '''A class to support a submit button'''
    submit = SubmitField('Submit')


@app.before_request
def before_request():
    if oidc.user_loggedin:
        g.user = oidc.user_getfield('preferred_username')
    else:
        g.user = None


@app.route('/')
def index():
    '''The main view function of the app'''
    return render_template('index.html', microservices=demo_microservices)


@app.route('/status')
# @oidc.require_login
def status():
    '''View function for the status of services and systems'''
    
    actions = [("Query all services", "allservices"),
               ("Query all systems","allsystems"),
               ("View available parameters", "parameters")]
    return render_template('status.html',actions=actions,microservices=demo_microservices)

@app.route("/status/allservices")
@oidc.require_login
def allservices():
    '''View function for query the status of all services availables in FirecREST'''

    response = requests.get(
         url = "{firecrest_url}/status/services".format(firecrest_url=app.config["FIRECREST_IP"]),
         headers = {"Authorization":"Bearer {oidc_token}".format(oidc_token=oidc.get_access_token())}   )

    return render_template("status/allservices.html", response=response,microservices=demo_microservices)

@app.route("/status/allsystems")
@oidc.require_login
def allsystems():
    '''View function for query the status of all services availables in FirecREST'''

    response = requests.get(
         url = "{firecrest_url}/status/systems".format(firecrest_url=app.config["FIRECREST_IP"]),
         headers = {"Authorization":"Bearer {oidc_token}".format(oidc_token=oidc.get_access_token())}   )

    return render_template("status/allsystems.html", response=response,microservices=demo_microservices)

@app.route("/status/parameters")
@oidc.require_login
def parameters():
    '''View function for query the status of all services availables in FirecREST'''

    response = requests.get(
         url = "{firecrest_url}/status/parameters".format(firecrest_url=app.config["FIRECREST_IP"]),
         headers = {"Authorization":"Bearer {oidc_token}".format(oidc_token=oidc.get_access_token())}   )

    return render_template("status/parameters.html", response=response, microservices=demo_microservices)

@app.route('/tasks')
@oidc.require_login
def tasks():
    '''View function for listing the FirecREST tasks'''
    response = requests.get(
         url = f"{app.config['FIRECREST_IP']}/tasks/",
         headers = {'Authorization': f'Bearer {oidc.get_access_token()}'})

    return render_template('tasks.html', response=response, microservices=demo_microservices)


@app.route('/tasks/<taskid>')
@oidc.require_login
def task(taskid):
    '''View function for listing the FirecREST tasks'''

    app.logger.info(request.args.get("data"))

    response = requests.get(
         url="{firecrest_url}/tasks/{taskid}".format(firecrest_url=app.config['FIRECREST_IP'],taskid=taskid),
         headers={'Authorization': f'Bearer {oidc.get_access_token()}'})

    if request.args.get("data") == "1":
        return response.json()

    return render_template("tasks/task.html",response=response,microservices=demo_microservices)



@app.route('/storage')
def storage():
    '''View function for listing the FirecREST tasks'''
    
    actions = [("External upload","upload"),
               ("External download","download"),
               ("Internal Transfer", "internal"),
                  ]
    return render_template('storage.html',actions=actions,microservices=demo_microservices)

@app.route('/storage/upload', methods=['GET', 'POST'])
@oidc.require_login
def storage_upload():
    '''View function for uploading large files'''
    form = ExternalUploadForm()
    response = None
    if request.method == "GET":
        form.targetPath.data = "{}/{}".format(app.config["HOME_DIR"], g.user)
    elif form.validate_on_submit() or request.method == "POST":
        target_path = form.targetPath.data
        source_path = form.sourcePath.data
        response = requests.post(
            url=f"{app.config['FIRECREST_IP']}/storage/xfer-external/upload",
            headers={'Authorization': f'Bearer {oidc.get_access_token()}'},
            data={'targetPath': target_path, 'sourcePath': source_path})
        
        if response.ok:
            taskid = response.json()["task_id"]

            response = requests.get(
                url="{firecrest_url}/tasks/{taskid}".format(firecrest_url=app.config['FIRECREST_IP'], taskid=taskid),
                headers={'Authorization': f'Bearer {oidc.get_access_token()}'})

            return render_template("tasks/task.html", response=response,microservices=demo_microservices)

    return render_template('storage/upload.html', form=form, response=response,microservices=demo_microservices)

@app.route('/storage/download', methods=['GET', 'POST'])
@oidc.require_login
def storage_download():
    '''View function for downloading large files'''
    form = ExternalDownloadForm()
    response = None
    if request.method == "GET":
        form.sourcePath.data = "{}/{}".format(app.config["HOME_DIR"], g.user)
    elif form.validate_on_submit() or request.method == "POST":
        source_path = form.sourcePath.data

        app.logger.info("Source path: {}".format(source_path))

        response = requests.post(
            url=f"{app.config['FIRECREST_IP']}/storage/xfer-external/download",
            headers={'Authorization': f'Bearer {oidc.get_access_token()}'},
            data={'sourcePath': source_path})

        if response.ok:
            taskid = response.json()["task_id"]
            # response = requests.get("{host}/tasks/{taskid}".format(taskid=taskid,host=request.url_root))
            # return 
            response = requests.get(
                url="{firecrest_url}/tasks/{taskid}".format(firecrest_url=app.config['FIRECREST_IP'], taskid=taskid),
                headers={'Authorization': f'Bearer {oidc.get_access_token()}'})

            return render_template("tasks/task.html", response=response, microservices=demo_microservices)

    return render_template('storage/download.html', form=form, response=response, microservices=demo_microservices)

@app.route('/storage/internal', methods=['GET', 'POST'])
@oidc.require_login
def internal_transfer():
    '''View function for uploading large files'''
    form = StorageInternalForm()
    response = None
    if form.validate_on_submit() or request.method == "POST":
        target_path = form.targetPath.data
        source_path = form.sourcePath.data
        jobName     = form.jobName.data
        action      = form.action.data

        data_2 = {'targetPath': target_path, 'sourcePath': source_path}
        data_1 = {'targetPath': target_path}

        if jobName != '':
            data_1["jobName"] = jobName
            data_2["jobName"] = jobName

        if action in ["cp","mv","rsync"]:

            response = requests.post(
                url=f"{app.config['FIRECREST_IP']}/storage/xfer-internal/{action}",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}'},
                data=data_2)

        elif action == "rm":

            response = requests.post(
                url=f"{app.config['FIRECREST_IP']}/storage/xfer-internal/{action}",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}'},
                data=data_1)

        else:
            app.logger.info("Action {} doesn't exist".format(action))
            response = make_response("Action {} doesn't exist".format(action),status_code=400)

    return render_template('storage/xfer-internal.html', form=form, response=response, machine=app.config['STORAGE_JOBS_MACHINE'], microservices=demo_microservices)

@app.route('/compute')
def compute():
    '''View function for listing the FirecREST tasks'''
    
    actions = [ ("Submit a job", "submit"),
                ("Query all active jobs", "jobs"),
                ("Account information", "acct")
              ]
    return render_template('compute.html',actions=actions,microservices=demo_microservices)

@app.route('/compute/jobs', methods=['GET', 'POST'])
@oidc.require_login
def alljobs():
    '''View function for listing the FirecREST tasks'''

    form = ListJobsForm()
    response = None
    machine = None
    
    if request.method == "POST":
        machine = request.args.get("machinename")
        if machine == None:
            #submit = True
            machine = form.machine.data
    
        response = requests.get(
            url=f"{app.config['FIRECREST_IP']}/compute/jobs",
            headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                     'X-Machine-Name': machine})

    return render_template('compute/jobs.html',form=form,response=response,machine=machine,microservices=demo_microservices)

@app.route('/compute/jobs/<jobid>', methods=['GET', 'POST'])
@oidc.require_login
def job(jobid):
    '''View function for listing the FirecREST tasks'''

    form = SingleJobForm()
    response = None
    form.jobid.data = jobid

    machine = request.args.get("machine")

    if machine == None:
        return render_template('compute/job.html', form=form, response={"error":"machinename not set"})

    response = requests.get(
        url=f"{app.config['FIRECREST_IP']}/compute/jobs/{jobid}",
        headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                 'X-Machine-Name': machine})

    return render_template('compute/job.html',form=form,response=response, microservices=demo_microservices)

@app.route('/compute/acct', methods=['GET', 'POST'])
@oidc.require_login
def acct():
    '''View function for listing the FirecREST tasks'''

    form = ListAcctForm()
    response = None

    if form.validate_on_submit() or request.method == "POST":
        flash(f'Querying jobs on: {form.machine.data}')
        machine = form.machine.data
        starttime = form.starttime.data
        endtime = form.endtime.data
        response = requests.get(
            url=f"{app.config['FIRECREST_IP']}/compute/acct?starttime={starttime}&endtime={endtime}",
            headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                     'X-Machine-Name': machine})

    return render_template('compute/acct.html',form=form,response=response, microservices=demo_microservices)

@app.route('/compute/submit', methods=['GET', 'POST'])
@oidc.require_login
def submitjob():
    '''View function for job submission'''
    form = JobForm()
    filename = None
    data = None
    response = None
    machine = None
    if request.method == "POST":

        fileOrForm = form.fileOrForm.data

        if fileOrForm == "form":
            partition = form.partition.data
            constraint = form.constraint.data
            jobName = form.jobName.data
            nNodes = form.nNodes.data
            nTasksPerCore = form.nTasksPerCore.data
            nTasksPerNode = form.nTasksPerNode.data
            nCpusPerTask  = form.nCpusPerTask.data
            email = form.email.data
            command = form.command.data
            app.logger.info("Partition {}".format(partition))

            try:
                td = tempfile.mkdtemp(prefix="job")
                app.logger.info("temp dir {}".format(td))
                filename = td + "/sbatch-job.sh"

                
                sbatch_file = open(filename, "w")

                sbatch_file.write("#! /bin/bash\n")
                
                if jobName != "":
                    sbatch_file.write("#SBATCH --job-name={}\n".format(jobName))
                # sbatch_file.write("#SBATCH --time={jobTime}\n".format(jobTime=jobTime))
                sbatch_file.write("#SBATCH --error=job-%j.err\n")
                sbatch_file.write("#SBATCH --output=job-%j.out\n")
                sbatch_file.write("#SBATCH --nodes={}\n".format(nNodes))
                # sbatch_file.write("#SBATCH --ntasks-per-core={}\n".format(nTasksPerCore))
                sbatch_file.write("#SBATCH --ntasks-per-node={}\n".format(nTasksPerNode))
                sbatch_file.write("#SBATCH --cpus-per-task={}\n".format(nTasksPerNode))
                sbatch_file.write("#SBATCH --partition={}\n".format(partition))
                if constraint != "":
                    sbatch_file.write("#SBATCH --constraint={}\n".format(constraint))
                if email != "":
                    sbatch_file.write("#SBATCH --mail-type=ALL\n")
                    sbatch_file.write("#SBATCH --mail-user={}\n".format(email))


                sbatch_file.write("\n")
                sbatch_file.write("{}\n".format(command))

                sbatch_file.close()

            except IOError as ioe:
                app.logger.error(ioe.message)
                response = make_response(jsonify(description="Failed creating sbatch file",error=ioe.message),400)

            files = {'file': open(filename, 'rb')}

            machine = form.machine.data
            response = requests.post(
                url=f"{app.config['FIRECREST_IP']}/compute/jobs/upload",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                     'X-Machine-Name': machine},
                files=files)
           
                           
            
        else:
            filename = secure_filename(form.upload.data.filename)
            data = form.upload.data            

            machine = form.machine.data
            response = requests.post(
                url=f"{app.config['FIRECREST_IP']}/compute/jobs/upload",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                     'X-Machine-Name': machine},
                files={"file":(filename,data.stream)})

    partitions = app.config["PARTITIONS"]

    return render_template('compute/submitjob.html', response=response,
                           data=data, form=form,machine=machine, microservices=demo_microservices, partitions=partitions)

@app.route('/compute/cancel/<jobid>', methods=['GET', 'POST'])
@oidc.require_login
def cancel(jobid):
    '''View function for listing the FirecREST tasks'''

    form = CancelJobForm()
    response = None
    form.jobid.data = jobid
    machine = request.args.get("machine")
    if machine != None:
        form.machine.data = machine

    if form.validate_on_submit():
        # flash(f'Querying jobs on: {form.machine.data}')

        response = requests.delete(
            url=f"{app.config['FIRECREST_IP']}/compute/jobs/{jobid}",
            headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                 'X-Machine-Name': machine})

    return render_template('compute/canceljob.html',response=response,form=form, machine=machine, microservices=demo_microservices)

@app.route('/utilities', methods=["GET", "POST"])
@oidc.require_login
def utilities():
    '''View function for listing directories and files'''

    form = PathForm()

    if request.method != "POST":
        path = request.args.get("targetPath")
        machine = request.args.get("machinename")

        if path != None:
            submit = True
            form.filepath.data = path
        else:
            form.filepath.data = "{}/{}".format(app.config["HOME_DIR"], g.user)
            path = form.filepath.data

        if machine != None:
            form.machine.data = machine
        else:
            machine = form.machine.choices[0][0] # first element of choices tuple
    else:
        path = form.filepath.data
        machine = form.machine.data

    app.logger.info("Machine: {}".format(machine))
    app.logger.info("Path: {}".format(path))

    response = requests.get(
            url=f"{app.config['FIRECREST_IP']}/utilities/ls",
            headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                     'X-Machine-Name': machine},
            params={'targetPath': path})

    return render_template('utilities.html', machine=machine, path=path, response=response, form=form, microservices=demo_microservices)

@app.route("/utilities/copy", methods=["POST"])
@oidc.require_login
def copy():

    form = PathForm()
    result = None
    error_headers = None

    if request.method == "POST":
        try:
            machine = request.form["machine"]
            sourcePath = request.form["sourcePath"]
            targetPath = request.form["targetPath"]
            path = request.form["path"]

            response = requests.post(
                url=f"{app.config['FIRECREST_IP']}/utilities/copy",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                data={'targetPath': targetPath, 'sourcePath': sourcePath}
            )


            if not response.ok:
                result = "error"
                error_headers = ["X-Machine-Does-Not-Exist","X-Machine-Not-Available","X-Permission-Denied","X-Invalid-Path","X-Timeout"]
                description = response.json()["description"]
                for header,value in response.headers.items():
                    if header in error_headers:
                        description = value
                        break
                        
                        
            else:
                result = "success"
                description = response.json()["description"]


            response = requests.get(
                url=f"{app.config['FIRECREST_IP']}/utilities/ls",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                params={'targetPath': path})
           

            return render_template('utilities.html', machine=machine, path=path, response=response, form=form,result=result,description=description, microservices=demo_microservices)
        except Exception as e:
            app.logger.error(e)

@app.route("/utilities/rename",methods=["POST"])
@oidc.require_login
def rename():

    form = PathForm()
    result = None
    error_headers = None

    if request.method == "POST":
        try:
            machine = request.form["machine"]
            sourcePath = request.form["sourcePath"]
            targetPath = request.form["targetPath"]
            path = request.form["path"]
            

            response = requests.put(
                url=f"{app.config['FIRECREST_IP']}/utilities/rename",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                data={'targetPath': targetPath, 'sourcePath': sourcePath}
            )


            if not response.ok:
                result = "error"
                error_headers = ["X-Exists","X-Not-Found","X-Machine-Does-Not-Exist","X-Machine-Not-Available","X-Permission-Denied","X-Invalid-Path","X-Timeout"]
                description = response.json()["description"]
                for header,value in response.headers.items():
                    if header in error_headers:
                        description = value
                        break
                        
                        
            else:
                result = "success"
                description = response.json()["description"]


            response = requests.get(
                url=f"{app.config['FIRECREST_IP']}/utilities/ls",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                params={'targetPath': path})
           

            return render_template('utilities.html', machine=machine, path=path, response=response, form=form,result=result,description=description, microservices=demo_microservices)
        except Exception as e:
            app.logger.error(e)

@app.route("/utilities/rm",methods=["POST"])
@oidc.require_login
def rm():

    form = PathForm()
    result = None
    error_headers = None

    if request.method == "POST":
        try:
            machine = request.form["machine"]
            targetPath = request.form["targetPath"]
            path = request.form["path"]

            response = requests.delete(
                url=f"{app.config['FIRECREST_IP']}/utilities/rm",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                data={'targetPath': targetPath}
            )


            if not response.ok:
                result = "error"
                error_headers = ["X-Exists","X-Not-Found","X-Machine-Does-Not-Exist","X-Machine-Not-Available","X-Permission-Denied","X-Invalid-Path","X-Timeout"]
                description = "Error deleting file {}".format(targetPath)
                for header,value in response.headers.items():
                    if header in error_headers:
                        description = value
                        break
                        
                        
            else:
                result = "success"
                description = "Succesfully deleted file {}".format(targetPath)


            response = requests.get(
                url=f"{app.config['FIRECREST_IP']}/utilities/ls",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                params={'targetPath': path})
           

            return render_template('utilities.html', machine=machine, path=path, response=response, form=form,result=result,description=description, microservices=demo_microservices)
        except Exception as e:
            app.logger.error(e)


@app.route("/utilities/chmod",methods=["POST"])
@oidc.require_login
def chmod():

    form = PathForm()
    result = None
    error_headers = None

    if request.method == "POST":
        try:
            machine = request.form["machine"]
            targetPath = request.form["targetPath"]
            path = request.form["path"]
            mode = request.form["mode"]

            response = requests.put(
                url=f"{app.config['FIRECREST_IP']}/utilities/chmod",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                data={'targetPath': targetPath, "mode":mode}
            )

            if not response.ok:
                result = "error"
                error_headers = ["X-Exists","X-Not-Found","X-Machine-Does-Not-Exist","X-Machine-Not-Available","X-Permission-Denied","X-Invalid-Path","X-Timeout", "X-Invalid-Mode"]
                description = response.json()["description"]
                for header,value in response.headers.items():
                    if header in error_headers:
                        description = value
                        break
                        
                        
            else:
                result = "success"
                description = response.json()["description"]


            response = requests.get(
                url=f"{app.config['FIRECREST_IP']}/utilities/ls",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                params={'targetPath': path})
           

            return render_template('utilities.html', machine=machine, path=path, response=response, form=form,result=result,description=description, microservices=demo_microservices)
        except Exception as e:
            app.logger.error(e)

@app.route("/utilities/download",methods=["POST"])
@oidc.require_login
def download():

    form = PathForm()
    result = None
    error_headers = None

    if request.method == "POST":
        try:
            machine = request.form["machine"]
            sourcePath = request.form["sourcePath"]
            path = request.form["path"]
            
            response = requests.get(
                url=f"{app.config['FIRECREST_IP']}/utilities/download",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                params={'sourcePath': sourcePath}
            )

            if not response.ok:
                result = "error"
                error_headers = ["X-Exists","X-Not-Found","X-Machine-Does-Not-Exist","X-Machine-Not-Available","X-Permission-Denied","X-Invalid-Path","X-Timeout", "X-Invalid-Group","X-Invalid-Owner", "X-Size-Limit"]
                description = response.json()["description"]
                for header,value in response.headers.items():
                    if header in error_headers:
                        description = value
                        break
            else:
                result = "success"
                description = "File downloaded"

                fileName = sourcePath.split("/")[-1]

                return send_file(BytesIO(response.content), as_attachment=True, attachment_filename=fileName)

            response = requests.get(
                url=f"{app.config['FIRECREST_IP']}/utilities/ls",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                params={'targetPath': path})

            return render_template('utilities.html', machine=machine, path=path, response=response, form=form,result=result,description=description, microservices=demo_microservices)
        except Exception as e:
            app.logger.error(e)




@app.route("/utilities/chown",methods=["POST"])
@oidc.require_login
def chown():

    form = PathForm()
    result = None
    error_headers = None

    if request.method == "POST":
        try:
            machine = request.form["machine"]
            targetPath = request.form["targetPath"]
            path = request.form["path"]
            owner = request.form["owner"]
            group = request.form["group"]

            response = requests.put(
                url=f"{app.config['FIRECREST_IP']}/utilities/chown",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                data={'targetPath': targetPath, 'owner':owner, "group":group}
            )

            if not response.ok:
                result = "error"
                error_headers = ["X-Exists","X-Not-Found","X-Machine-Does-Not-Exist","X-Machine-Not-Available","X-Permission-Denied","X-Invalid-Path","X-Timeout", "X-Invalid-Group","X-Invalid-Owner"]
                description = response.json()["description"]
                for header,value in response.headers.items():
                    if header in error_headers:
                        description = value
                        break
            else:
                result = "success"
                description = response.json()["description"]


            response = requests.get(
                url=f"{app.config['FIRECREST_IP']}/utilities/ls",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                params={'targetPath': path})

            return render_template('utilities.html', machine=machine, path=path, response=response, form=form,result=result,description=description, microservices=demo_microservices)
        except Exception as e:
            app.logger.error(e)



@app.route('/utilities/upload', methods=['GET', 'POST'])
@oidc.require_login
def upload():
    '''View function for listing the files of the user'''
    form = PathForm()
    result = None
    error_headers = None

    if request.method == "POST":
        try:
            machine = request.form["machine"]
            targetPath = request.form["targetPath"]
            uploadFile = request.files['upload']
            filename = secure_filename(uploadFile.filename)

            _tmpdir = tempfile.mkdtemp("", "demo", "/tmp")
            local_path = os.path.join(_tmpdir, filename)

            uploadFile.save(local_path)

            response = requests.post(
                url=f"{app.config['FIRECREST_IP']}/utilities/upload",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                data={'targetPath': targetPath},
                files={'file': open(local_path,"rb")}
            )

            os.remove(local_path)
            os.rmdir(_tmpdir)


            if not response.ok:
                result = "error"
                error_headers = ["X-Exists","X-Not-Found","X-Machine-Does-Not-Exist","X-Machine-Not-Available","X-Permission-Denied","X-Invalid-Path","X-Timeout", "X-Invalid-Group","X-Invalid-Owner"]
                description = response.json()["description"]
                for header,value in response.headers.items():
                    if header in error_headers:
                        description = value
                        break
            else:
                result = "success"
                description = response.json()["description"]


            response = requests.get(
                url=f"{app.config['FIRECREST_IP']}/utilities/ls",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                params={'targetPath': targetPath})


            return render_template('utilities.html', machine=machine, path=targetPath,response=response, form=form,result=result,description=description, microservices=demo_microservices)
        except Exception as e:
            app.logger.error(e)



@app.route('/utilities/mkdir', methods=['GET', 'POST'])
@oidc.require_login
def mkdir():
    '''View function for listing the files of the user'''
    form = PathForm()
    result = None
    error_headers = None

    if request.method == "POST":
        try:
            machine = request.form["machine"]
            targetPath = request.form["targetPath"]
            path = request.form["path"]
            

            response = requests.post(
                url=f"{app.config['FIRECREST_IP']}/utilities/mkdir",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                data={'targetPath': targetPath}
            )

            if not response.ok:
                result = "error"
                error_headers = ["X-Exists","X-Not-Found","X-Machine-Does-Not-Exist","X-Machine-Not-Available","X-Permission-Denied","X-Invalid-Path","X-Timeout", "X-Invalid-Group","X-Invalid-Owner"]
                description = response.json()["description"]
                for header,value in response.headers.items():
                    if header in error_headers:
                        description = value
                        break
                        
                        
            else:
                result = "success"
                description = response.json()["description"]


            response = requests.get(
                url=f"{app.config['FIRECREST_IP']}/utilities/ls",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                params={'targetPath': path})
           

            return render_template('utilities.html', machine=machine, path=path, response=response, form=form,result=result,description=description, microservices=demo_microservices)
        except Exception as e:
            app.logger.error(e)

@app.route('/utilities/checksum', methods=['GET', 'POST'])
@oidc.require_login
def checksum():
    '''View function for listing the files of the user'''
    form = PathForm()
    result = None
    error_headers = None

    if request.method == "POST":
        try:
            machine = request.form["machine"]
            targetPath = request.form["targetPath"]
            path = request.form["path"]
            

            response = requests.get(
                url=f"{app.config['FIRECREST_IP']}/utilities/checksum",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                params={'targetPath': targetPath}
            )

            if not response.ok:
                result = "error"
                error_headers = ["X-Exists","X-Not-Found","X-Machine-Does-Not-Exist","X-Machine-Not-Available","X-Permission-Denied","X-Invalid-Path","X-Timeout", "X-Invalid-Group","X-Invalid-Owner"]
                description = response.json()["description"]
                for header,value in response.headers.items():
                    if header in error_headers:
                        description = value
                        break
                        
                        
            else:
                result = "success"
                description = f"{response.json()['description']}: {response.json()['output']}"


            response = requests.get(
                url=f"{app.config['FIRECREST_IP']}/utilities/ls",
                headers={'Authorization': f'Bearer {oidc.get_access_token()}',
                         'X-Machine-Name': machine},
                params={'targetPath': path})
           

            return render_template('utilities.html', machine=machine, path=path, response=response, form=form,result=result,description=description, microservices=demo_microservices)
        except Exception as e:
            app.logger.error(e)

@app.route('/api', methods=['GET', 'POST'])
@oidc.require_login
def api():
    form = TestAPIForm()

    if request.method == "POST":
        service = form.microservice.data
        query   = form.query.data
        machine = form.machine.data
        method  = form.method.data

        param_names = request.form.getlist("parameter")
        param_values= request.form.getlist("value")

        

        url = f"{app.config['FIRECREST_IP']}/{service}/{query}"
        headers = {"X-Machine-Name": machine, "Authorization": f"Bearer {oidc.get_access_token()}"}


        if method == "DELETE":
            
            data = {}

            for i in range(len(param_names)):
                data[param_names[i]] = param_values[i]

            response=requests.delete(url=url, headers=headers, data=data)
        elif method == "POST":
            data = {}

            for i in range(len(param_names)):
                data[param_names[i]] = param_values[i]

            response=requests.post(url=url, headers=headers, data=data)
        elif method == "PUT":
            data = {}

            for i in range(len(param_names)):
                data[param_names[i]] = param_values[i]

            response=requests.put(url=url, headers=headers, data=data)

        elif method == "GET":
            params = {}

            for i in range(len(param_names)):
                params[param_names[i]] = param_values[i]

            response=requests.get(url=url, headers=headers,params=params)
            
        # form.resp_json.data = response.text
        form.resp_headers.data = response.headers

        return render_template('api.html', form=form, microservices=demo_microservices, response=response)

    return render_template('api.html', form=form, microservices=demo_microservices, response = None)


@app.route("/login")
@oidc.require_login
def login():
    '''View function for logging in'''
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    '''View function for logging out'''
    oidc.logout()
    return redirect(url_for("index"))


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
    SSL_PEM = app.config['SSL_PEM']
    SSL_KEY = app.config['SSL_KEY']

    if not USE_SSL:
        app.run(host='0.0.0.0')
    else:
        app.run(host='0.0.0.0', ssl_context=(SSL_PEM, SSL_KEY))

