#
#  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
#  This migration script coverts Redis task keys from
#  versions < 1.14.1 

import os
import re
import redis
import redis.exceptions as redis_exceptions
import json

#PERSISTENCE_IP   = os.environ.get("F7T_PERSISTENCE_IP")
#PERSIST_PORT = os.environ.get("F7T_PERSIST_PORT")
#PERSIST_PWD  = os.environ.get("F7T_PERSIST_PWD")

PERSISTENCE_IP = 'localhost'
PERSIST_PORT = '6379'
PERSIST_PWD = 'rediS2200'


old_key_pattern = re.compile("^task_([a-z0-9]+)+$")
def key_is_old_format(key:str):
    return old_key_pattern.match(key)

new_key_pattern = re.compile("^task_([A-z0-9_@\\.\\!$%&-]+):([A-z0-9_@\\.\\!$%&-]+):([a-z0-9]+)$")
def key_is_new_format(key:str):
    return new_key_pattern.match(key)

def generate_task_id(task) -> str:
    return "task_{user}:{service}:{id}".format(user=task["user"],service=task["service"],id=task["task_id"])


r = redis.StrictRedis(host=PERSISTENCE_IP,port=PERSIST_PORT,db=0,password=PERSIST_PWD)

num_old_keys:int=0
num_new_keys:int=0
num_errors:int=0

for task_id in r.scan_iter(match="task_*"):

    json_task = r.get(task_id)
    task = json.loads(json_task.decode('latin-1'))
    ttl  = r.ttl(task_id)
    
    if(key_is_old_format(task_id.decode('latin-1'))):
        num_old_keys+=1
        print("Found: '{key}' with TTL:{ttl}".format(key=task_id.decode('latin-1'),ttl=ttl))
        new_key = generate_task_id(task)
        if(not key_is_new_format(new_key)):
            print("Error: new key format mismatch!")
            num_errors+=1
        else:
            print("-> new key: '{key}'".format(key=new_key))
            #r.setex(new_key,ttl,json_task)
            old_taks = r.get(task_id)
            new_task = r.get(new_key)
            if(old_taks==new_task):
                print("Success!")
                num_new_keys=+1
            else:
                print("Error: new task data does not match original!")
                num_errors+=1
        print("\n")
print("\n\n")
print("==================================================")
print("Migration completed!")
print("==================================================")
print("Old keys found:\t\t{num}".format(num=num_old_keys))
print("New keys generated:\t{num}".format(num=num_new_keys))
print("Errors:\t\t\t{num}".format(num=num_errors))
print("==================================================")
