#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from flask import Flask, request, jsonify, send_file
import paramiko

from logging.handlers import TimedRotatingFileHandler
import tempfile, os, socket, logging
from werkzeug.utils import secure_filename
from werkzeug.exceptions import BadRequestKeyError

from math import ceil
from cscs_api_common import check_header, get_username,exec_remote_command, create_certificates, \
    get_buffer_lines, clean_err_output


CERTIFICATOR_URL = os.environ.get("CERTIFICATOR_URL")
STATUS_IP        = os.environ.get("STATUS_IP")

UTILITIES_PORT   = os.environ.get("UTILITIES_PORT", 5000)

AUTH_HEADER_NAME = 'Authorization'

UTILITIES_TIMEOUT = int(os.environ.get("UTILITIES_TIMEOUT"))

# SYSTEMS: list of ; separated systems allowed
SYSTEMS_PUBLIC  = os.environ.get("SYSTEMS_PUBLIC").strip('\'"').split(";")
# internal machines for file operations
SYS_INTERNALS   = os.environ.get("SYSTEMS_INTERNAL_UTILITIES").strip('\'"').split(";")

debug = os.environ.get("DEBUG_MODE", None)

#max file size for upload/download in MB
MAX_FILE_SIZE=int(os.environ.get("UTILITIES_MAX_FILE_SIZE"))

app = Flask(__name__)
# max content lenght for upload in bytes
app.config['MAX_CONTENT_LENGTH'] = int(MAX_FILE_SIZE) * 1024 * 1024


# function to check if pattern is in string
def in_str(stringval,words):
    try:
        stringval.index(words)
        return True
    except AttributeError: #if is not str, then is byte encoding
        stringval = stringval.decode('latin-1')
        stringval.index(words)
        return True
    except ValueError:
        return False # if words never found


# performs upload via SSH client of paramiko
# user = remote cluster user
# system = remote cluster
# local_path = full local path (Filesystem) of the file to be uploaded
# remote_path = remote dir (cluster) in which file will be uploaded - must exists

def paramiko_upload(auth_header, cluster, local_path, remote_path):

    fileName = local_path.split("/")[-1]

    # get certificate
    cert_list = create_certificates(auth_header, cluster)

    if cert_list[0] == None:
        result = {"error": 1, "msg": "Certificator error: {msg}".format(msg=cert_list[2])}
        return result

    [pub_cert, pub_key, priv_key, temp_dir] = cert_list

    username = get_username(auth_header)

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
                           timeout=2)

        ftp_client = client.open_sftp()

        try:
            local_file = open(local_path, "rb")
            local_data = local_file.read()
        except Exception as e:
            app.logger.error(e.message)
            result = {"error": 1, "msg": e.message}
        finally:
            local_file.close()

        remote_path_file = "{remote_path}/{filename}".format(remote_path=remote_path, filename=fileName)
        try:
            remote_file = ftp_client.file(remote_path_file, "w")
            remote_file.write(local_data)
        except Exception as e:
            app.logger.error(e.message)
            result = {"error": 1, "msg": e.message}
        finally:
            remote_file.close()

        ftp_client.close()
        client.close()

        result = {"error": 0, "msg": remote_path_file}

    except paramiko.ssh_exception.NoValidConnectionsError as e:
        app.logger.error(type(e))
        if e.errors:
            for k, v in e.errors.items():
                app.logger.error("errorno: {errno}".format(errno=v.errno))
                app.logger.error("strerr: {strerr}".format(strerr=v.strerror))
                result = {"error": v.errno, "msg": v.strerror}

    # second: time out
    except socket.timeout as e:
        app.logger.error(type(e))
        # timeout has not errno
        app.logger.error(e)
        result = {"error": 1, "msg": e}
    except IOError as e:
        app.logger.error("IOError")
        app.logger.error(e.message)
        app.logger.error(e.filename)
        app.logger.error(e.errno)
        app.logger.error(e.strerror)
        result = {"error": e.errno, "msg": "IOError"}

    except Exception as e:
        app.logger.error(e)
        result = {"error": 1, "msg": e}

    # removing temporary keys, certs and dirs
    os.remove(pub_cert)
    os.remove(pub_key)
    os.remove(priv_key)
    os.rmdir(temp_dir)

    return result


def paramiko_download(auth_header, cluster, path):

    fileName = path.split("/")[-1]

    # get certificate
    cert_list = create_certificates(auth_header, cluster)

    if cert_list[0] == None:
        result = {"error": 1, "msg": "Certificator error: {msg}".format(msg=cert_list[2])}
        return result

    [pub_cert, pub_key, priv_key, temp_dir] = cert_list

    username = get_username(auth_header)

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
                       timeout=2)

        # check file size not over SIZE_LIMIT

        action = "stat --dereference -c %s -- '{path}'".format(path=path)
        stdin, stdout, stderr = client.exec_command(action)

        # error status
        errno = stderr.channel.recv_exit_status()
        errda = clean_err_output(stderr.channel.recv_stderr(1024))

        # if error raised shouldn't continue
        if errno != 0 or errda != "":
            app.logger.error("({errno}) --> {stderr}".format(errno=errno, stderr=errda))
            app.logger.error(stdout.channel.recv_exit_status())
            result = {"error": 1, "msg": errda.rstrip()}
        else:  # no error on stat, now checking file size
            outlines = get_buffer_lines(stdout)
            app.logger.error(errda)
            app.logger.error(errno)
            app.logger.info("({errno}) --> File Size: {stdout}".format(errno=errno, stdout=outlines))

            file_size = int(outlines) # in bytes

            # if file is too big:
            if file_size > MAX_FILE_SIZE*(1024*1024):
                app.logger.warning("File size exceeds limit")
                result={"error":-3,"msg":"File size exceeds limit"}
            elif file_size == 0:
                # may be empty, a special file or a directory, just return empty
                _tmpdir=tempfile.mkdtemp("", "cscs", "/tmp")
                local_path = "{tempdir}/{fileName}".format(tempdir=_tmpdir, fileName=fileName)
                local_file = open(local_path,"wb")
                local_file.close()
                result = {"error": 0, "msg": local_path}
            else:
                #if file isn't too big, download
                ftp_client = client.open_sftp()
                _tmpdir=tempfile.mkdtemp("", "cscs", "/tmp")
                local_path = "{tempdir}/{fileName}".format(tempdir=_tmpdir,fileName=fileName)

                remote_file = ftp_client.file(path,"r")
                local_file  = open(local_path,"wb")

                remote_data = remote_file.read()
                local_file.write(remote_data)

                remote_file.close()
                local_file.close()

                ftp_client.close()
                result = {"error": 0, "msg": local_path}

            # close connection
            client.close()

    except paramiko.ssh_exception.NoValidConnectionsError as e:
        app.logger.error(type(e))
        if e.errors:
            for k, v in e.errors.items():

                app.logger.error("errorno: {errno}".format(errno=v.errno))
                app.logger.error("strerr: {strerr}".format(strerr=v.strerror))
                result = {"error": v.errno, "msg": v.strerror}

    # second: time out
    except socket.timeout as e:
        app.logger.error(type(e))
        # timeout has not errno
        app.logger.error(e)
        result = {"error": 1, "msg": e}
    except IOError as e:
        logging.error(e.message, exc_info=True)
        app.logger.error("IOError")
        app.logger.error(e.message)
        app.logger.error(e.errno)
        app.logger.error(e.strerror)
        result = {"error": e.errno, "msg": "IOError"}
    except Exception as e:
        logging.error(e, exc_info=True)
        app.logger.error(e)
        result = {"error":1, "msg":e}


    os.remove(pub_cert)
    os.remove(pub_key)
    os.remove(priv_key)
    os.rmdir(temp_dir)

    return result


## file: determines the type of file of path
## params:
##  - path: Filesystem path (Str) *required
##  - machinename: str *required

@app.route("/file", methods=["GET"])
def file_type():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # PUBLIC endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Error in file operation", error="Machine does not exists"), 400, header

    # iterate over SYSTEMS list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    try:
        path = request.args.get("targetPath")
    except BadRequestKeyError as e:
        return jsonify(description="Error in file operation",error="'targetPath' query string missing"), 400


    action = "timeout {timeout} file -b -- '{path}'".format(timeout=UTILITIES_TIMEOUT, path=path)

    retval = exec_remote_command(auth_header, machine, action)

    error_str = retval["msg"]

    if retval["error"] != 0:
        if retval["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(description="Error in file operation"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Error in file operation"), 400, header

        #in case of permission for other user
        if in_str(error_str,"Permission"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Error in file operation"), 404, header

        # otherwise, generic error
        return jsonify(description="Error in file operation", error=error_str), 404

    # for file, is not an error (echo $? = 0) if the file doesn't exist or user has not permissions
    if in_str(error_str, "cannot open"):
        header = {"X-Invalid-Path": "{path} is an invalid path".format(path=path)}
        return jsonify(description="Error in file operation"), 400, header

    if in_str(error_str, "read permission"):
        header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
        return jsonify(description="Error in file operation"), 400, header

    return jsonify(description="Operation completed", out=retval["msg"]), 200


## chmod: Change Mode of path in Filesystem
## params:
##  - path: Filesystem path (Str) *required
##  - mode: numerical mode for file (e.g.: 700, 644, etc) *required
##  - machinename: str *required

@app.route("/chmod",methods=["PUT"])
def chmod():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Error in chmod operation", error="Machine does not exists"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    # getting path from request form
    try:
        path = request.form["targetPath"]
    except BadRequestKeyError:
        return jsonify(description="Error in chmod operation",error="'targetPath' query string missing"), 400

    # getting chmode's mode from request form:
    try:
        mode = request.form["mode"]
    except BadRequestKeyError:
        return jsonify(description="Error in chmod operation", error="mode query string missing"), 400

    # using -c flag for verbose mode in stdout
    action = "timeout {timeout} chmod -v '{mode}' -- '{path}'".format(timeout=UTILITIES_TIMEOUT,mode=mode,path=path)

    retval = exec_remote_command(auth_header, machine, action)

    if retval["error"] != 0:
        if retval["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(description="Error in chmod operation"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Error in chmod operation"), 400, header

        error_str = retval["msg"]

        if in_str(error_str, "cannot access"):
            header = {"X-Invalid-Path": "{path} is an invalid path".format(path=path)}
            return jsonify(description="Error in chmod operation"), 400, header

        if in_str(error_str, "not permitted"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Error in chmod operation"), 400, header

        if in_str(error_str, "invalid mode"):
            header = {"X-Invalid-Mode": "{mode} is an invalid mode".format(mode=mode)}
            return jsonify(description="Error in chmod operation"), 400, header

        #otherwise, generic error
        return jsonify(description="Error in chmod operation", error=error_str), 404

    return jsonify(description="Operation completed", out=retval["msg"]), 200


## chown: Change owner of path in Filesystem
## params:
##  - path: Filesystem path (Str) *required
##  - owner: new user owner of the path file
##  - group: new group owner of the path file
##  - machinename: str *required

@app.route("/chown",methods=["PUT"])
def chown():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Error in chown operation", error="Machine does not exists"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    try:
        path = request.form["targetPath"]
    except BadRequestKeyError:
        return jsonify(description="Error in chown operation",error="'targetPath' query string missing"), 400

    if path == None:
        return jsonify(description="Error in chown operation",error="'targetPath' query string missing"), 400
    try:
        owner = request.form["owner"]
    except Exception:
        owner = ""

    try:
        group = request.form["group"]
    except Exception:
        group = ""

    if owner == "" and group == "":
        return jsonify(description="Error in chown operation", error="group and/or owner should be set"), 400


    action = "timeout {timeout} chown -v '{owner}':'{group}' -- '{path}'".format(
                    timeout=UTILITIES_TIMEOUT,owner=owner,group=group,path=path)

    retval = exec_remote_command(auth_header, machine, action)

    if retval["error"] != 0:
        if retval["error"] == -2:
            header = {"X-Machine-Not-Available": "Machine is not available"}
            return jsonify(description="Error in chown operation"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Error in chown operation"), 400, header

        error_str = retval["msg"]

        if in_str(error_str,"cannot access"):
            header={"X-Invalid-Path":"{path} is an invalid path".format(path=path)}
            return jsonify(description="Error in chown operation"), 400, header

        if in_str(error_str,"not permitted"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Error in chown operation"), 400, header

        if in_str(error_str,"invalid group"):
            header = {"X-Invalid-Group": "{group} is an invalid group".format(group=group)}
            return jsonify(description="Error in chown operation"), 400, header

        if in_str(error_str,"invalid user"):
            header = {"X-Invalid-Owner": "{owner} is an invalid user".format(owner=owner)}
            return jsonify(description="Error in chown operation"), 400, header

        return jsonify(description="Error in chown operation", error=error_str), 404


    return jsonify(description="Operation completed", out=retval["msg"]), 200


## ls: List Directory contents
## params:
##  - path: Filesystem path (Str) *required
##  - showhidden: Bool
##  - machinename: str *required

@app.route("/ls",methods=["GET"])
def list_directory():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Error listing contents of path", error="Machine does not exists"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    try:
        path = request.args.get("targetPath")
    except BadRequestKeyError:
        return jsonify(description="Error in ls operation",error="'targetPath' query string missing"), 400

    if path == None:
        return jsonify(description="Error listing contents of path",error="path query string missing"), 400

    # if set shows entrys starting with . (not including . and/or .. dirs)
    try:
        showhidden = request.args.get("showhidden", None)
    except BadRequestKeyError:
        return jsonify(description="Error in ls operation", error="option error"), 400

    showall = ""
    if showhidden != None:
        showall = "-A"

    # action = "ls -l {showall} --time-style=+%Y-%m-%dT%H:%M:%S -- '{path}' | awk ' {{ print $7 \"|\" substr ($1,0,1) \"|\"$9\"|\"$3\"|\"$4\"|\" substr ($1,2,9) \"|\"$6\"|\"$5\";\" }} ' ".format(
    #         path=path, showall=showall)

    # changed since bash only captures errors from the last command in pipeline, and this always was OK
    action = "timeout {timeout} ls -l {showall} --time-style=+%Y-%m-%dT%H:%M:%S -- '{path}' ".format(path=path, showall=showall,timeout=UTILITIES_TIMEOUT)

    retval = exec_remote_command(auth_header, machine, action)

    if retval["error"] != 0:
        error_str=retval["msg"]

        if retval["error"] == 113:
            header = {"X-Machine-Not-Available":"Machine is not available"}
            return jsonify(description="Error listing contents of path"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Error listing contents of path"), 400, header

        if in_str(error_str,"cannot access"):

            header={"X-Invalid-Path":"{path} is an invalid path".format(path=path)}
            return jsonify(description="Error listing contents of path"), 400, header

        if in_str(error_str,"cannot open"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Error listing contents of path"), 400, header

        # generic not caught error
        return jsonify(description="Error listing contents of path",error=retval["msg"]), 400


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

    # calculate the list to retrieve
    if pageSize and pageNumber:

        pageNumber = float(pageNumber)
        pageSize   = float(pageSize)

        totalPages = int(ceil(float(totalSize) / float(pageSize)))

        app.logger.info("Total Size: {totalSize}".format(totalSize=totalSize))
        app.logger.info("Total Pages: {totalPages}".format(totalPages=totalPages))


        if pageNumber < 1 or pageNumber>totalPages:
            app.logger.warning("pageNumber ({pageNumber}) greater than total pages ({totalPages})".format(pageNumber=pageNumber, totalPages=totalPages))
            app.logger.warning("Showing all results")
        else:
            beg_reg=int((pageNumber-1)*pageSize)
            end_reg=int(pageNumber*pageSize-1)

            app.logger.info("Initial reg {beg_reg}, final reg: {end_reg}".format(beg_reg=beg_reg, end_reg=end_reg))

            fileList = fileList[beg_reg:end_reg+1]


    outLabels = ["name","type","link_target","user","group","permissions","last_modified","size"]

    # labels taken from list to dict with default value: ""
    outList = []

    logging.info("Length of file list: {}".format(len(fileList)))

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

    return jsonify(descr="List of contents of path",output=outList), 200


## mkdir: Make Directory
## params:
##  - path: Filesystem path (Str) *required
##  - p: -p, --parents no error if existing, make parent directories as needed (bool)
##  - machinename: str *required

@app.route("/mkdir",methods=["POST"])
def make_directory():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Error creating directory", error="Machine does not exists"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    try:
        path = request.form["targetPath"]
    except BadRequestKeyError:
        return jsonify(description="Error creating directory", error="'targetPath' query string missing"), 400

    try:
        p = request.form["p"]
        parent = "-p"
    except BadRequestKeyError:
        parent = ""

    action = "timeout {timeout} mkdir {parent} -- '{path}'".format(timeout=UTILITIES_TIMEOUT,path=path,parent=parent)

    retval = exec_remote_command(auth_header, machine, action)

    if retval["error"] != 0:
        error_str=retval["msg"]

        if retval["error"] == 113:
            header = {"X-Machine-Not-Available":"Machine is not available"}
            return jsonify(description="Error creating directory"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Error creating directory"), 400, header

        if in_str(error_str,"No such file"):
            header={"X-Invalid-Path":"{path} is an invalid path".format(path=path)}
            return jsonify(description="Error creating directory"), 400, header

        if in_str(error_str,"Permission denied"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Error creating directory"), 400, header

        if in_str(error_str,"File exists"):
            header = {"X-Exists": "{path} already exists".format(path=path)}
            return jsonify(description="Error creating directory"), 400, header

        return jsonify(description="Error creating directory",error=retval["msg"]), 400


    return jsonify(description="Directory created", output=""), 201


## rename/move
## params:
##  - oldpath: Filesystem path of current object (Str) *required
##  - newpath: Filesystem path of new object (Str) *required
##  - machinename: str *required

@app.route("/rename", methods=["PUT"])
def rename():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Error on rename operation", error="Machine does not exists"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    try:
        sourcePath = request.form["sourcePath"]
    except BadRequestKeyError:
        return jsonify(description="Error on rename operation", error="'sourcePath' query string missing"), 400

    try:
        targetPath = request.form["targetPath"]
    except BadRequestKeyError:
        return jsonify(description="Error on rename operation", error="newpath query string missing"), 400

    # action to execute
    action = "echo n | timeout {timeout} mv -i -- '{sourcePath}' '{targetPath}'".format(
                            timeout=UTILITIES_TIMEOUT,sourcePath=sourcePath, targetPath=targetPath)

    retval = exec_remote_command(auth_header, machine, action)

    if retval["error"] != 0:
        error_str=retval["msg"]

        if retval["error"] == 113:
            header = {"X-Machine-Not-Available":"Machine is not available"}
            return jsonify(description="Error on rename operation"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Error on rename operation"), 400, header

        # error no such file
        if in_str(error_str,"No such file"):
            if in_str(error_str,"cannot stat"):
                header={"X-Not-Found":"{sourcePath} not found.".format(sourcePath=sourcePath)}
                return jsonify(description="Error on rename operation"), 400, header

            if in_str(error_str,"cannot move"):
                header = {"X-Invalid-Path": "{sourcePath} and/or {targetPath} are invalid paths.".format(sourcePath=sourcePath,targetPath=targetPath)}
                return jsonify(description="Error on rename operation"), 400, header

        # permission denied
        if in_str(error_str,"Permission denied"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}
            return jsonify(description="Error on rename operation"), 400, header

        # if already exists, not overwrite (-i)
        if in_str(error_str,"overwrite"):
            header = {"X-Exists": "{targetPath} already exists".format(targetPath=targetPath)}
            return jsonify(description="Error on rename operation"), 400, header

        return jsonify(description="Error on rename operation",error=error_str), 400


    return jsonify(description="Success to rename file or directory.", output=""), 200



## copy cp
## params:
##  - sourcepath: Filesystem path of object to be copied (Str) *required
##  - targetpath: Filesystem path of copied object (Str) *required
##  - machinename: str *required

@app.route("/copy", methods=["POST"])
def copy():
    return common_operation(request, "copy", "POST")

## common code for file operations: copy, rename (move)
def common_operation(request, command, method):
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Error on " + command + " operation", error="Machine does not exists"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    try:
        sourcePath = request.form["sourcePath"]
    except BadRequestKeyError:
        return jsonify(description="Error on " + command + " operation", error="'sourcePath' query string missing"), 400

    try:
        targetPath = request.form["targetPath"]
    except BadRequestKeyError:
        return jsonify(description="Error on " + command + " operation", error="target query string missing"), 400

    
    if command == "copy":
        # action to execute
        # -i is for interactive, when user asks for confirmation, given with "echo n"
        # -r is for recursivelly copy files into directories
        action = "echo n | timeout {timeout} cp -i -dR --preserve=all -- '{sourcePath}' '{targetPath}'".format(
            timeout=UTILITIES_TIMEOUT, sourcePath=sourcePath, targetPath=targetPath)
    elif command == "rename":
        action = "echo n | timeout {timeout} mv -i -- '{sourcePath}' '{targetPath}'".format(
            timeout=UTILITIES_TIMEOUT, sourcePath=sourcePath, targetPath=targetPath)


    retval = exec_remote_command(auth_header, machine, action)

    if retval["error"] != 0:
        error_str=retval["msg"]

        if retval["error"] == 113:
            header = {"X-Machine-Not-Available":"Machine is not available"}
            return jsonify(description="Error on " + command + " operation"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Error on " + command + " operation"), 400, header

        # error no such file
        if in_str(error_str,"No such file"):
            if in_str(error_str,"cannot stat"):
                header={"X-Not-Found":"{sourcePath} not found.".format(sourcePath=sourcePath)}
                return jsonify(description="Error on " + command + " operation"), 400, header

            # copy: cannot create, rename: cannot move
            if in_str(error_str, "cannot create") or in_str(error_str,"cannot move"):
                header = {"X-Invalid-Path": "{sourcePath} and/or {targetPath} are invalid paths.".format(sourcePath=sourcePath, targetPath=targetPath)}
                return jsonify(description="Error on " + command + " operation"), 400, header

        # permission denied
        if in_str(error_str,"Permission denied"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}
            return jsonify(description="Error on " + command + " operation"), 400, header

        # if already exists, not overwrite (-i)
        if in_str(error_str,"overwrite"):
            header = {"X-Exists": "{targetPath} already exists".format(targetPath=targetPath)}
            return jsonify(description="Error on " + command + " operation"), 400, header

        return jsonify(description="Error on copy operation"), 400

    return jsonify(description="Success to " + command + " file or directory.", output=""), 201



## Remove file or directory
## params:
## - path: path to the file or directory to be removed
## - X-Machine-Name: system

@app.route("/rm", methods=["DELETE"])
def rm():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Error on delete operation", error="Machine does not exists"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    try:
        path = request.form["targetPath"]
    except BadRequestKeyError:
        return jsonify(description="Error on delete operation",error="'targetPath' query string missing"), 400

    # action to execute
    # -r is for recursivelly delete files into directories
    action = "echo n | timeout {timeout} rm -r -- '{path}'".format(timeout=UTILITIES_TIMEOUT,path=path)

    retval = exec_remote_command(auth_header, machine, action)

    if retval["error"] != 0:
        error_str=retval["msg"]

        if retval["error"] == 113:
            header = {"X-Machine-Not-Available":"Machine is not available"}
            return jsonify(description="Error on delete operation"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Error on delete operation"), 400, header

        # error no such file
        if in_str(error_str,"No such file"):
            if in_str(error_str,"cannot remove"):
                header = {"X-Invalid-Path": "{path} is an invalid path.".format(path=path)}
                return jsonify(description="Error on delete operation"), 400, header

        # permission denied
        if in_str(error_str,"Permission denied"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or path"}
            return jsonify(description="Error on delete operation"), 400, header

        return jsonify(description="Error on delete operation"), 400


    return jsonify(description="Success to delete file or directory.", output=""), 204



## Symbolic Link
## params:
##  - target: path to target that the symlink will point to (Str) *required
##  - source: absolute path to the new symlink *required
##  - machinename: str *required

@app.route("/symlink", methods=["POST"])
def symlink():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Failed to create symlink", error="Machine does not exists"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    try:
        linkPath = request.form["linkPath"]
    except BadRequestKeyError:
        return jsonify(description="Failed to create symlink",error="'linkPath' query string missing"), 400

    try:
        targetPath = request.form["targetPath"]
    except BadRequestKeyError:
        return jsonify(description="Failed to create symlink",error="'targetPath' query string missing"), 400

    action = "timeout {timeout} ln -s -- '{targetPath}' '{linkPath}'".format(
                timeout=UTILITIES_TIMEOUT,targetPath=targetPath,linkPath=linkPath)

    retval = exec_remote_command(auth_header, machine, action)

    if retval["error"] != 0:
        error_str=retval["msg"]

        if retval["error"] == 113:
            header = {"X-Machine-Not-Available":"Machine is not available"}
            return jsonify(description="Failed to create symlink"), 400, header

        if retval["error"] == 124:
            header = {"X-Timeout": "Command has finished with timeout signal"}
            return jsonify(description="Failed to create symlink"), 400, header

        # error no such file
        if in_str(error_str,"No such file"):
            header = {"X-Invalid-Path": "{targetPath} and/or {linkPath} are invalid paths.".format(targetPath=targetPath,linkPath=linkPath)}
            return jsonify(description="Failed to create symlink"), 400, header

        # permission denied
        if in_str(error_str,"Permission denied"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}
            return jsonify(description="Failed to create symlink"), 400, header

        # if already exists
        if in_str(error_str,"File exists"):
            header = {"X-Exists": "{linkPath} already exists".format(linkPath=linkPath)}
            return jsonify(description="Failed to create symlink"), 400, header


        return jsonify(description="Failed to create symlink"), 400


    return jsonify(description="Success create the symlink"), 201

## Returns the file from the specified path on the {machine} filesystem
## params:
##  - path: path to the file to download *required
##  - machinename: str *required

@app.route("/download", methods=["GET"])
def download():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Failed to download file", error="Machine does not exists"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    path = request.args.get("sourcePath")

    if path == None:
        return jsonify(description="Failed to download file",error="'sourcePath' query string missing"), 400

    # copy file from remote machinename to local filesystem
    retval = paramiko_download(auth_header, machine, path)

    # posible errors

    # IOError 13: Permission denied
    if retval["error"] == 13:
        header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}
        return jsonify(description="Failed to download file"), 400, header

    # IOError 2: no such file
    if retval["error"] == 2:
        header = {"X-Invalid-Path": "{path} is invalid.".format(path=path)}
        return jsonify(description="Failed to download file"), 400, header

    # IOError -2: name or service not known
    if retval["error"] == -2:
        header = {"X-Machine-Not-Available": "Machine is not available"}
        return jsonify(description="Failed to download file"), 400, header
    # custom error raises when file size > SIZE_LIMIT env var
    if retval["error"] == -3:
        header = {"X-Size-Limit": "File exceeds size limit"}
        return jsonify(description="Failed to download file"), 400, header

    if retval["error"] != 0:
        if in_str(retval["msg"],"Permission"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}
            return jsonify(description="Failed to download file"), 400, header
        else:
            return jsonify(description="Failed to download file"), 400

    local_file = retval["msg"]
    file_name  = path.split("/")[-1]


    return send_file(local_file,
                     mimetype="application/octet-stream",
                     attachment_filename=file_name,
                     as_attachment=True)


## Returns the file from the specified path on the {machine} filesystem
## params:
##  - path: path to the file to download *required
##  - machinename: str *required

## error handler for files above SIZE_LIMIT -> app.config['MAX_CONTENT_LENGTH']
@app.errorhandler(413)
def request_entity_too_large(error):
    app.logger.error(error)
    return jsonify(description="Failed to upload file. The file is over {} MB".format(MAX_FILE_SIZE)), 413

@app.route("/upload", methods=["POST"])
def upload():
    # checks if AUTH_HEADER_NAME is set
    try:
        auth_header = request.headers[AUTH_HEADER_NAME]
    except KeyError as e:
        app.logger.error("No Auth Header given")
        return jsonify(description="No Auth Header given"), 401

    if not check_header(auth_header):
        return jsonify(description="Invalid header"), 401

    try:
        machinename = request.headers["X-Machine-Name"]
    except KeyError as e:
        app.logger.error("No machinename given")
        return jsonify(description="No machine name given"), 400

    # public endpoints from Kong to users
    if machinename not in SYSTEMS_PUBLIC:
        header = {"X-Machine-Does-Not-Exists": "Machine does not exists"}
        return jsonify(description="Failed to upload file", error="Machine does not exists"), 400, header

    # iterate over systems list and find the endpoint matching same order
    for i in range(len(SYSTEMS_PUBLIC)):
        if SYSTEMS_PUBLIC[i] == machinename:
            machine = SYS_INTERNALS[i]
            break

    path = request.form["targetPath"]

    if path == None:
        return jsonify(description="Failed to upload file", error="'targetPath' query string missing"), 400

    if 'file' not in request.files:
        return jsonify(description="Failed to upload file", error="No file in query"), 400

    file = request.files['file']

    app.logger.info("Length: {length}".format(length=file.content_length))
    app.logger.info("Headers: {headers}".format(headers=file.headers))

    if file.filename == '':
        return jsonify(description="Failed to upload file", error="No file selected"), 400

    filename = secure_filename(file.filename)

    _tmpdir = tempfile.mkdtemp("", "cscs-uploads", "/tmp")
    local_path = os.path.join(_tmpdir, filename)

    file.save(local_path)

    retval=paramiko_upload(auth_header, machine, local_path, path)

    os.remove(local_path)
    os.rmdir(_tmpdir)

    # IOError 13: Permission denied
    if retval["error"] == 13:
        header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}
        return jsonify(description="Failed to upload file"), 400, header

    # IOError 2: no such file
    if retval["error"] == 2:
        header = {"X-Invalid-Path": "{path} is invalid.".format(path=path)}
        return jsonify(description="Failed to upload file"), 400, header

    # IOError -2: name or service not known
    if retval["error"] == -2:
        header = {"X-Machine-Not-Available": "Machine is not available"}
        return jsonify(description="Failed to upload file"), 400, header

    if retval["error"] != 0:
        if in_str(retval["msg"],"Permission"):
            header = {"X-Permission-Denied": "User does not have permissions to access machine or paths"}
            return jsonify(description="Failed to upload file"), 400, header
        else:
            return jsonify(description="Failed to upload file"), 400

    return jsonify(description="File upload successful"), 201


# get status for status microservice
# only used by STATUS_IP otherwise forbidden
@app.route("/status", methods=["GET"])
def status():
    app.logger.info("Test status of service")

    if request.remote_addr != STATUS_IP:
        app.logger.warning("Invalid remote address: {addr}".format(addr=request.remote_addr))
        return jsonify(error="Invalid access"), 403

    return jsonify(success="ack"), 200


if __name__ == "__main__":
    # log handler definition
    # timed rotation: 1 (interval) rotation per day (when="D")
    logHandler = TimedRotatingFileHandler('/var/log/utilities.log', when='D', interval=1)

    logFormatter = logging.Formatter('%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                                     '%Y-%m-%d:%H:%M:%S')
    logHandler.setFormatter(logFormatter)
    logHandler.setLevel(logging.DEBUG)

    # get app log (Flask+werkzeug+python)
    logger = logging.getLogger()

    # set handler to logger
    logger.addHandler(logHandler)

    # run app
    # debug = False, so output redirects to log files
    app.run(debug=debug, host='0.0.0.0', port=UTILITIES_PORT)
