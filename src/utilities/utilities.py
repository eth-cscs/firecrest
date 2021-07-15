#
#  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from flask import Flask, request, jsonify, send_file

from logging.handlers import TimedRotatingFileHandler
import tempfile, os, socket, logging
from werkzeug.utils import secure_filename
from werkzeug.exceptions import BadRequestKeyError

import base64
import io
import json
from math import ceil
from flask_opentracing import FlaskTracing
from jaeger_client import Config
import opentracing

from cscs_api_common import check_auth_header, exec_remote_command, check_command_error, get_boolean_var, validate_input

CERTIFICATOR_URL = os.environ.get("F7T_CERTIFICATOR_URL")

UTILITIES_PORT   = os.environ.get("F7T_UTILITIES_PORT", 5000)

AUTH_HEADER_NAME = 'Authorization'

UTILITIES_TIMEOUT = int(os.environ.get("F7T_UTILITIES_TIMEOUT"))

# SYSTEMS: list of ; separated systems allowed
SYSTEMS_PUBLIC  = os.environ.get("F7T_SYSTEMS_PUBLIC").strip('\'"').split(";")
# internal machines for file operations
SYS_INTERNALS   = os.environ.get("F7T_SYSTEMS_INTERNAL_UTILITIES").strip('\'"').split(";")

debug = get_boolean_var(os.environ.get("F7T_DEBUG_MODE", False))

#max file size for upload/download in MB, internally used in bytes
MAX_FILE_SIZE_BYTES = int(os.environ.get("F7T_UTILITIES_MAX_FILE_SIZE")) * 1024 * 1024

### SSL parameters
USE_SSL = get_boolean_var(os.environ.get("F7T_USE_SSL", False))
SSL_CRT = os.environ.get("F7T_SSL_CRT", "")
SSL_KEY = os.environ.get("F7T_SSL_KEY", "")

TRACER_HEADER = "uber-trace-id"

app = Flask(__name__)
# max content lenght for upload in bytes
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE_BYTES

JAEGER_AGENT = os.environ.get("F7T_JAEGER_AGENT", "").strip('\'"')
if JAEGER_AGENT != "":
    config = Config(
        config={'sampler': {'type': 'const', 'param': 1 },
            'local_agent': {'reporting_host': JAEGER_AGENT, 'reporting_port': 6831 },
            'logging': True,
            'reporter_batch_size': 1},
            service_name = "utilities")
    jaeger_tracer = config.initialize_tracer()
    tracing = FlaskTracing(jaeger_tracer, True, app)
else:
    jaeger_tracer = None
    tracing = None


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

## file: determines the type of file of path
## params:
##  - path: Filesystem path (Str) *required
##  - machinename: str *required

@app.route("/file", methods=["GET"])
@check_auth_header
def file_type():
    return common_fs_operation(request, "file")


## chmod: Change Mode of path in Filesystem
## params:
##  - path: Filesystem path (Str) *required
##  - mode: numerical mode for file (e.g.: 700, 644, etc) *required
##  - machinename: str *required

@app.route("/chmod", methods=["PUT"])
@check_auth_header
def chmod():
    return common_fs_operation(request, "chmod")


## chown: Change owner of path in Filesystem
## params:
##  - path: Filesystem path (Str) *required
##  - owner: new user owner of the path file
##  - group: new group owner of the path file
##  - machinename: str *required

@app.route("/chown", methods=["PUT"])
@check_auth_header
def chown():
    return common_fs_operation(request, "chown")


## ls: List Directory contents
## params:
##  - path: Filesystem path (Str) *required
##  - showhidden: Bool
##  - machinename: str *required

@app.route("/ls", methods=["GET"])
@check_auth_header
def list_directory():
    return common_fs_operation(request, "ls")


## parse ls output
def ls_parse(request, retval):
    # file List is retorned as a string separated for a $ character
    fileList = []
    if len(retval["msg"].split("$")) == 1:
        # if only one line is returned, there are two cases:
        # 1. 'total 0': means directory was empty, so fileList is kept empty
        # 2. 'r.....   some_file.txt': means 'ls' was to only one file: 'ls /home/user/some.txt'
        if retval["msg"][0:5]!='total':
            fileList = retval["msg"].split("$")
    else:
        fileList = retval["msg"].split("$")[1:]

    totalSize = len(fileList)

    # if pageSize and number were set:
    pageSize = request.args.get("pageSize")
    pageNumber = request.args.get("pageNumber")

    app.logger.info(f"PageSize: {pageSize}. PageNumber: {pageNumber}")

    # calculate the list to retrieve
    if pageSize and pageNumber:
        pageNumber = float(pageNumber)
        pageSize   = float(pageSize)

        totalPages = int(ceil(float(totalSize) / float(pageSize)))

        app.logger.info(f"Total Size: {totalSize}")
        app.logger.info(f"Total Pages: {totalPages}")

        if pageNumber < 1 or pageNumber>totalPages:
            app.logger.warning(f"pageNumber ({pageNumber}) greater than total pages ({totalPages})")
            #app.logger.warning("Showing all results")
        else:
            beg_reg=int((pageNumber-1)*pageSize)
            end_reg=int(pageNumber*pageSize-1)
            app.logger.info(f"Initial reg {beg_reg}, final reg: {end_reg}")
            fileList = fileList[beg_reg:end_reg+1]


    outLabels = ["name","type","link_target","user","group","permissions","last_modified","size"]

    # labels taken from list to dict with default value: ""
    outList = []

    logging.info(f"Length of file list: {len(fileList)}")

    for files in fileList:
        line = files.split()

        try:
            symlink = line[8] # because of the -> which is 7
        except IndexError:
            symlink = ""

        outDict = {outLabels[0]:line[6],
                outLabels[1]:line[0][0],
                outLabels[2]:symlink,
                outLabels[3]:line[2],
                outLabels[4]:line[3],
                outLabels[5]:line[0][1:],
                outLabels[6]:line[5],
                outLabels[7]:line[4]
                }

        outList.append(outDict)

    return outList


## mkdir: Make Directory
## params:
##  - path: Filesystem path (Str) *required
##  - p: -p, --parents no error if existing, make parent directories as needed (bool)
##  - machinename: str *required

@app.route("/mkdir", methods=["POST"])
@check_auth_header
def make_directory():
    return common_fs_operation(request, "mkdir")


## Returns the content (head) from the specified path on the {machine} filesystem
## params:
##  - path: path to the file to download *required
##  - machinename: str *required

@app.route("/view", methods=["GET"])
@check_auth_header
def view():
    try:
        resp = common_fs_operation(request, "stat")
        if resp[1] != 200:
            return resp
        out = json.loads(resp[0].data.decode())
    except:
        return jsonify(description='Error on stat operation', output=''), 400

    file_size = int(out["output"]) # in bytes

    if file_size > MAX_FILE_SIZE_BYTES:
        app.logger.warning("File size exceeds limit")
        # custom error raises when file size > SIZE_LIMIT env var
        header = {"X-Size-Limit": "File exceeds size limit"}
        return jsonify(description="Failed to view file content"), 400, header

    # TODO: download with base64 to avoid encoding conversion and string processing ?
    return common_fs_operation(request, "head")


## checksum: Print or check SHA256 (256-bit) checksums
## params:
##  - targetPath: Filesystem path (Str) *required##
##  - machinename: str *required

@app.route("/checksum", methods=["GET"])
@check_auth_header
def checksum():
    return common_fs_operation(request, "checksum")


## rename/move
## params:
##  - oldpath: Filesystem path of current object (Str) *required
##  - newpath: Filesystem path of new object (Str) *required
##  - machinename: str *required

@app.route("/rename", methods=["PUT"])
@check_auth_header
def rename():
    return common_fs_operation(request, "rename")


## copy cp
## params:
##  - sourcepath: Filesystem path of object to be copied (Str) *required
##  - targetpath: Filesystem path of copied object (Str) *required
##  - machinename: str *required
@app.route("/copy", methods=["POST"])
@check_auth_header
def copy():
    return common_fs_operation(request, "copy")


## common code for file operations:
def common_fs_operation(request, command):
    try:
        system_name = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if system_name not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exist": "Machine does not exist"}
        return jsonify(description=f"Error on {command} operation", error="Machine does not exist"), 400, header

    # select index in the list corresponding with machine name
    system_idx = SYSTEMS_PUBLIC.index(system_name)
    system_addr = SYS_INTERNALS[system_idx]

    # get targetPath to apply command
    tn = 'targetPath'
    if request.method == 'GET':
        targetPath = request.args.get("targetPath", None)
        if (targetPath == None) and (command in ['base64', 'stat']):
            # TODO: review API
            tn = "sourcePath"
            targetPath = request.args.get("sourcePath", None)
    else: # DELETE, POST, PUT
        targetPath = request.form.get("targetPath", None)

    v = validate_input(targetPath)
    if v != "":
        return jsonify(description=f"Error on {command} operation", error=f"'{tn}' {v}"), 400

    if command in ['copy', 'rename']:
        sourcePath = request.form.get("sourcePath", None)
        v = validate_input(sourcePath)
        if v != "":
            return jsonify(description=f"Error on {command} operation", error=f"'sourcePath' {v}"), 400

    file_content = None
    file_transfer = None
    success_code = 200

    if command == "base64":
        action = f"base64 --wrap=0 -- '{targetPath}'"
        file_transfer = 'download'
    elif command == "checksum":
        action = f"sha256sum -- '{targetPath}'"
    elif command == "chmod":
        mode = request.form.get("mode", None)
        v = validate_input(mode)
        if v != "":
            return jsonify(description="Error on chmod operation", error=f"'mode' {v}"), 400
        action = f"chmod -v '{mode}' -- '{targetPath}'"
    elif command == "chown":
        owner = request.form.get("owner", "")
        group = request.form.get("group", "")
        if owner == "" and group == "":
            return jsonify(description="Error in chown operation", error="group or owner must be set"), 400
        v = validate_input(owner + group)
        if v != "":
            return jsonify(description="Error in chown operation", error=f"group or owner {v}"), 400
        action = f"chown -v '{owner}':'{group}' -- '{targetPath}'"
    elif command == "copy":
        # -r is for recursivelly copy files into directories
        action = f"cp --force -dR --preserve=all -- '{sourcePath}' '{targetPath}'"
        success_code = 201
    elif command == "file":
        # -b: do not prepend filenames to output lines
        action = f"file -b -- '{targetPath}'"
    elif command == "head":
        action = f"head -c {MAX_FILE_SIZE_BYTES} -- '{targetPath}'"
        file_transfer = 'download'
    elif command == "ls":
        # if set shows entrys starting with . (not including . and/or .. dirs)
        showhidden = request.args.get("showhidden", None)
        showall = ""
        if showhidden != None:
            showall = "-A"
        action = f"ls -l {showall} --time-style=+%Y-%m-%dT%H:%M:%S -- '{targetPath}'"
    elif command == "mkdir":
        try:
            p = request.form["p"]
            parent = "-p"
        except BadRequestKeyError:
            parent = ""
        action = f"mkdir {parent} -- '{targetPath}'"
        success_code = 201
    elif command == "rename":
        action = f"mv --force -- '{sourcePath}' '{targetPath}'"
    elif command == "rm":
        # -r is for recursivelly delete files into directories
        action = f"rm -r --interactive=never -- '{targetPath}'"
        success_code = 204
    elif command == "stat":
        action = f"stat --dereference -c %s -- '{targetPath}'"
    elif command == "symlink":
        linkPath = request.form.get("linkPath", None)
        v = validate_input(linkPath)
        if v != "":
            return jsonify(description="Failed to create symlink", error=f"'linkPath' value {v}"), 400
        action = f"ln -s -- '{targetPath}' '{linkPath}'"
        success_code = 201
    elif command == "upload":
        try:
            if 'file' not in request.files:
                return jsonify(description="Failed to upload file", error="No file in query"), 400
            file = request.files['file']
            app.logger.info(f"Upload length: {file.content_length}")
            #app.logger.info(f"Upload headers: {file.headers}")
            v = validate_input(file.filename)
            if v != "":
                return jsonify(description="Failed to upload file", error=f"Filename {v}"), 400
        except:
            return jsonify(description='Error on upload operation', output=''), 400
        filename = secure_filename(file.filename)
        action = f"cat > {targetPath}/{filename}"
        file_content = file.read()
        file_transfer = 'upload'
        success_code = 201
    else:
        app.logger.error(f"Unknown command on common_fs_operation: {command}")
        return jsonify(description="Error on internal operation", error="Internal error"), 400

    [headers, ID] = get_tracing_headers(request)
    action = f"ID={ID} timeout {UTILITIES_TIMEOUT} {action}"
    retval = exec_remote_command(headers, system_name ,system_addr, action, file_transfer, file_content)

    if retval["error"] != 0:
        error_str   = retval["msg"]
        error_code  = retval["error"]
        service_msg = f"Error on {command} operation"

        ret_data = check_command_error(error_str, error_code, service_msg)

        # if generic "error" not in the dict
        try:
            return jsonify(description=ret_data["description"], error=ret_data["error"]), ret_data["status_code"], ret_data["header"]
        except:
            return jsonify(description=ret_data["description"]), ret_data["status_code"], ret_data["header"]


    description = f"Success to {command} file or directory."
    output = ''
    if command == 'checksum':
        # return only hash, msg sintax:  hash filename
        output = retval["msg"].split()[0]
    elif command in ['base64', 'chmod', 'chown', 'file', 'head', 'stat']:
        output = retval["msg"]
    elif command == 'ls':
        description = "List of contents"
        output = ls_parse(request, retval)
    elif command == "upload":
        description="File upload successful"

    return jsonify(description=description, output=output), success_code



## Remove file or directory
## params:
## - path: path to the file or directory to be removed
## - X-Machine-Name: system

@app.route("/rm", methods=["DELETE"])
@check_auth_header
def rm():
    return common_fs_operation(request, "rm")


## Symbolic Link
## params:
##  - target: path to target that the symlink will point to (Str) *required
##  - source: absolute path to the new symlink *required
##  - machinename: str *required

@app.route("/symlink", methods=["POST"])
@check_auth_header
def symlink():
    return common_fs_operation(request, "symlink")


## Returns the file from the specified path on the {machine} filesystem
## params:
##  - path: path to the file to download *required
##  - machinename: str *required

@app.route("/download", methods=["GET"])
@check_auth_header
def download():
    try:
        # returns a tuple (json_msg, status_code [, header])
        resp = common_fs_operation(request, "stat")
        if resp[1] != 200:
            return resp
        out = json.loads(resp[0].data.decode())
    except Exception as e:
        app.logger.error(e)
        return jsonify(description='Error on stat operation', output=''), 400

    #TODO: check path doesn't finish with /
    path = request.args.get("sourcePath")
    file_name = secure_filename(path.split("/")[-1])

    try:
        file_size = int(out["output"]) # in bytes
        if file_size > MAX_FILE_SIZE_BYTES:
            app.logger.warning("File size exceeds limit")
            # custom error raises when file size > SIZE_LIMIT env var
            header = {"X-Size-Limit": "File exceeds size limit"}
            return jsonify(description="Failed to download file"), 400, header
        elif file_size == 0:
            # may be empty, a special file or a directory, just return empty
            data = io.BytesIO()
            data.seek(0)
            return send_file(data,
                     mimetype="application/octet-stream",
                     attachment_filename=file_name,
                     as_attachment=True)
    except Exception as e:
        app.logger.error(f"Download decode error: {e.message}")
        return jsonify(description="Failed to download file"), 400

    # download with base64 to avoid encoding conversion and string processing
    try:
        # returns a tuple (json_msg, status_code [, header])
        resp = common_fs_operation(request, "base64")
        if resp[1] != 200:
            return resp
        out = json.loads(resp[0].data.decode())
    except:
        return jsonify(description='Error on download operation', output=''), 400

    try:
        data = io.BytesIO()
        data.write(base64.b64decode(out["output"]))
        data.seek(0)
    except Exception as e:
        app.logger.error(f"Download decode error: {e.message}")
        return jsonify(description="Failed to download file"), 400

    return send_file(data,
                     mimetype="application/octet-stream",
                     attachment_filename=file_name,
                     as_attachment=True)



## error handler for files above SIZE_LIMIT -> app.config['MAX_CONTENT_LENGTH']
@app.errorhandler(413)
def request_entity_too_large(error):
    app.logger.error(error)
    return jsonify(description=f"Failed to upload file. The file is over {MAX_FILE_SIZE_BYTES} bytes"), 413


## Uploads file to specified path on the {machine} filesystem
## params:
##  - path: path to the file to download *required
##  - machinename: str *required

@app.route("/upload", methods=["POST"])
@check_auth_header
def upload():
    return common_fs_operation(request, "upload")


@app.route("/status", methods=["GET"])
def status():
    app.logger.info("Test status of service")
    return jsonify(success="ack"), 200


if __name__ == "__main__":
    # log handler definition
    # timed rotation: 1 (interval) rotation per day (when="D")
    logHandler = TimedRotatingFileHandler('/var/log/utilities.log', when='D', interval=1)

    logFormatter = logging.Formatter('%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                                     '%Y-%m-%dT%H:%M:%S')
    logHandler.setFormatter(logFormatter)
    logHandler.setLevel(logging.DEBUG)

    # get app log (Flask+werkzeug+python)
    logger = logging.getLogger()

    # set handler to logger
    logger.addHandler(logHandler)

    # run app
    # debug = False, so output redirects to log files
    if USE_SSL:
        app.run(debug=debug, host='0.0.0.0', port=UTILITIES_PORT, ssl_context=(SSL_CRT, SSL_KEY))
    else:
        app.run(debug=debug, host='0.0.0.0', port=UTILITIES_PORT)
