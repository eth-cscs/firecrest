#
#  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from hashlib import md5
import time
import json
import logging
import copy

logging.getLogger(__name__)

# common status codes
QUEUED   = "100"
PROGRESS = "101"
SUCCESS  = "200"
DELETED  = "300"
EXPIRED  = "301"
ERROR    = "400"

# upload process states
ST_URL_ASK = "110" # ask for Temp Form URL for upload xternal file to Object Storage
ST_URL_REC = "111" # received Temp Form URL for upload xternal file to Object Storage
ST_UPL_CFM = "112" # on upload process: upload to Object Storage confirmed
ST_DWN_BEG = "113" # on upload process: download from Object Storage to cluster started
ST_DWN_END = "114" # on upload process: download from Object Storage to cluster finished
ST_DWN_ERR = "115" # on upload process: download from Object Storage to cluster error

# download process states:
ST_UPL_BEG = "116" # on download process: start upload from filesystem to Object Storage
ST_UPL_END = "117" # on download process: upload from filesystem to Object Storage is finished
ST_UPL_ERR = "118" # on download process: upload from filesystem to Object Storage is erroneous



status_codes = { QUEUED  : "Queued",
                 SUCCESS : "Finished successfully",
                 PROGRESS: "In progress",
                 DELETED : "Deleted on request",
                 EXPIRED : "Marked for expiration in persistence",
                 ERROR   : "Finished with errors",

                 ST_URL_ASK: "Waiting for Form URL from Object Storage to be retrieved",
                 ST_URL_REC: "Form URL from Object Storage received",
                 ST_UPL_CFM: "Object Storage confirms that upload to Object Storage has finished",
                 ST_DWN_BEG: "Download from Object Storage to server has started",
                 ST_DWN_END: "Download from Object Storage to server has finished",
                 ST_DWN_ERR: "Download from Object Storage error",

                 ST_UPL_BEG: "Started upload from filesystem to Object Storage",
                 ST_UPL_END: "Upload from filesystem to Object Storage has finished succesfully",
                 ST_UPL_ERR: "Upload from filesystem to Object Storage has finished with errors"
                }



# task_id: unique task identificator
# status_code: standard status code as stated in status_code
# status_desc: standard status description as stated in status_codes
# data : last output result for the task (generated by client)



class AsyncTask():
    def __init__(self,task_id,user,service=None):

        self.task_id = task_id
        self.hash_id = self.get_hashid(task_id,user)
        self.status_code = QUEUED
        self.status_desc = status_codes[QUEUED]
        self.data = {}
        self.user = user
        self.service = service
        self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")

    # create hash_id as user-task_id MD5 encoded string
    # used for public access to info in Queue
    def get_hashid(self,task_id,user):
        data = "{user}-{task_id}".format(user=user,task_id=task_id)
        hash_object = md5(data.encode())
        hex_dig = hash_object.hexdigest()

        return hex_dig

    def is_owner(self,user):
        if self.user == user:
            return True
        return False

    # change defaulta data from {} to None
    def set_status(self,status,data=None):

        self.status_code = status
        self.status_desc = status_codes[str(status)]
        if data != None:
            # self.data = json.dumps(data)
            self.data = data
        self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")

    # return status for internal info (returns SSH "cert"ificate or "action")
    def get_internal_status(self):

        return {"hash_id":self.hash_id,
                "user": self.user,
                "status":self.status_code,
                "description":self.status_desc,                
                "data": self.data,
                "service":self.service,
                "last_modify":self.timestamp}

    # return status for public info, so task_id is discarded
    def get_status(self):

        # hide users certificate and action details
        # ["msg"]["certs"] & ["msg"]["action"]
        
                
        # if dict, then a deepcopy is needed, otherwise the dict in "msg" will be shallow copied
        if isinstance(self.data, dict):
        
            _data = copy.deepcopy(self.data)
        
            if len(_data) != 0:

                try:
                    if _data["msg"]["cert"] != None:
                        del _data["msg"]["cert"]
                        del _data["msg"]["action"]
                        del _data["msg"]["download_url"]
                except KeyError as e:
                    logging.warning(e.args)
                except Exception as e:
                    logging.warning(e.args)
        else:
            _data = self.data

        return {"hash_id":self.hash_id,
                "user": self.user,
                "status":self.status_code,
                "description":self.status_desc,                
                "data": _data,
                "service":self.service,
                "last_modify":self.timestamp}
