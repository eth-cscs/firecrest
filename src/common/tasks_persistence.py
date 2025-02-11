#
#  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import redis
import redis.exceptions as redis_exceptions
import logging
import json
from typing import Union, Dict

# create redis server connection, and return StrictRedis object
# otherwise returns None
def create_connection(host,port,passwd="",db=0) -> Union[redis.StrictRedis,None]:
    '''
    Creates a redis database connection using StrictRedis
    
    Parameters:
    - host (str): the hostname of redis database server
    - port (str): the port of redis database server
    - passwd (str) (optional, by default: ""): password of redis database server
    - db (int) (optional, by default: 0): number of database where data is stored in redis server

    Returns:
    - StrictRedis object if successful, otherwise None

    '''

    logging.info(f"Trying to start taskpersistance connection on host: {host}")

    try:
        r = redis.StrictRedis(host=host,port=port,db=db,password=passwd)
        return r
    except redis_exceptions.ResponseError as e:
        logging.error("Error on create_connection")
        logging.error(e)
        return None
    except redis_exceptions.AuthenticationError as e:
        logging.error("Error on create_connection")
        logging.error(e)
        return None
    except redis_exceptions.ConnectionError as e:
        logging.error("Error on create_connection")
        logging.error(e)
        return None
    except Exception as e:
        logging.error("Error on create_connection")
        logging.error(e)
        return None


def generate_task_id(task_id: int, task) -> str:
    # Note: consider escaping the ':' symbol from user and service
    return f"task_{task['user']}:{task['service']}:{task['system']}:{task_id}"


def key_parts(key: str) -> Dict[str, str]:
    keyparts = key.split(":")
    # to keep old keys that don't include "system" part
    if len(keyparts) == 3:
        return {"user": keyparts[0][5:],
                "service": keyparts[1],
                "task_id": keyparts[2]}

    if len(keyparts) == 4:
        return {"user": keyparts[0][5:],
                "service": keyparts[1],
                "system": keyparts[2],
                "task_id": keyparts[3]}

    return {"user": None,
            "service": None,
            "system": None,
            "task_id": None}


# incrementes task id by 1
def incr_last_task_id(r) -> Union[int, None]:
    '''
    Increments the internal task id counter in backend service by 1 (one)
    
    Parameters:
    - r (StrictRedis): object with connection details to a redis database
    
    Returns:
    - the new id (int) or if there was an error, None

    '''
    try:
        return r.incr("last_task_id",1)
    except Exception as e:
        logging.error("Error on incr_last_task_id")
        logging.error(e)
        return None

# save task status in redis server
# if success, returns True, otherwise, False
# task is the result of AsynkTask.get_status(), that's a dictionary with all fields
def save_task(r,task_id:int,task,exp_time=None) -> bool:
    '''
    Save the task in backend persistence service
    
    Parameters:
    - r (StrictRedis): object with connection details to a redis database
    - task (dict): task data 
    - exp_time (int) (optional, default=None): seconds to expire the task

    Returns:
    - A boolean, True if the task was correctly saved, otherwise False

    '''

    task_id = generate_task_id(task_id,task)
    # mapping = {"status":status, "user":user, "data":data}
    logging.info(f"save_task {task_id} in REDIS")

    try:
        # serialize json from task:
        jtask = json.dumps(task)
        if exp_time:
            r.setex(task_id,exp_time,jtask)
        else:
            r.set(task_id,jtask)
        return True
    except Exception as e:
        logging.error(e)
        logging.error(type(e))
        return False


# set task expiration
def set_expire_task(r,task_id:int,task,secs) -> bool:
    '''
    Set expiration time for a specific task
    
    Parameters:
    - r (StrictRedis): object with connection details to a redis database
    - task (dict): task data 
    - secs (int): seconds to expire the task

    Returns:
    - True if the task was correctly set as expired, otherwise False

    '''
    task_id = generate_task_id(task_id,task)
    try:
        # change to expire, because delete mantain deleted keys in redis
        # and iterate over them
        # r.delete(task_id)
        # redis.expire (key, seconds_to_live_from_now)
        logging.info(f"Marking as expired task {task_id} with TTL={secs} secs")
        return r.expire(task_id,secs)

    except Exception as e:
        logging.error("Error on expire task")
        logging.error(e)
        return False



# delete task from redis server
# if success, returns True, otherwise, False
def del_task(r,task_id,task) -> bool:
    '''
    Deletes a task by a given id (set expiration time for a specific task to 0)
    
    Parameters:
    - r (StrictRedis): object with connection details to a redis database
    - task (dict): task data
    
    Returns:
    - True if the task was correctly deleted, otherwise False

    '''

    # use set_expire_task with 0 seconds
    # it's better than delete
    return set_expire_task(r,task_id, task, 0)


# return all task in dict format
def get_all_tasks(r: redis.StrictRedis) -> Union[dict, None]:
    '''
    Return all valid tasks in the backend
    
    Parameters:
    - r (StrictRedis): object with connection details to a redis database
    
    Returns:
    - list of tasks

    '''

    task_dict = {}

    try:
        # changed use of keys for hscan, since keys has bad performance in big data sets
        # task_list = r.keys("task_*")
        # scan returns: [cursor, [list of keys]]
        # task_list = r.scan(cursor=0, match="task_*")[1]

        for redis_task_id in r.scan_iter(match="task_*"):

            # djson = r.hgetall(task_id)
            task_json = r.get(redis_task_id)

            # decode because redis stores it in Bytes not string
            task_json = task_json.decode('latin-1')
            task_id = key_parts(redis_task_id.decode('latin-1'))["task_id"]
            
            if task_id is None:
                continue

            # if d is empty, task_id was removed
            # this should be fixed with r.expire
            # if len(d) == 0:
            #    continue
            d = json.loads(task_json)
            task_dict[task_id] = d

        return task_dict


    except Exception as e:
        logging.error("Error on get_all_tasks")
        logging.error(e)
        return None

# returns all task from specific user:
def get_user_tasks(r,user,task_list=None, status_code=None) -> Union[dict,None]:
    '''
    Return current tasks filter by user
    
    Parameters:
    - r (StrictRedis): object with connection details to a redis database
    - user (str): username of the owner of the task
    - task_list (list[(str)]) (optional): list of hashes of tasks to return
    - status_code (str) (optional): status code of the tasks to return

    Returns:
    - list of tasks

    '''
    task_dict = {}

    try:
        # changed use of keys for hscan, since keys has bad performance in big data sets
        # task_list = r.keys("task_*")
        # scan_iter iterates between matching keys

        for task_id in r.scan_iter(match="task_{user}:*".format(user=user)):


            json_task = r.get(task_id)

            if json_task is None:
                continue

            # logging.info(json_task)
            # decode because redis stores it in Bytes not string
            task = json.loads(json_task.decode('latin-1'))

            try:
                _user = task["user"]
            except Exception as e:
                logging.error(type(e))
                continue

            # if user is the requested one
            if _user == user:

                # if status_code is required to be filtered
                if status_code != None:
                    # if the status doesn't match the list, then is skipped
                    if task["status"] not in status_code:
                        continue
                
                # if task_list is not empty, and not found in the sublist of user tasks, then is skipped
                if (task_list != None) and (task["hash_id"] not in task_list):
                    continue

                task_dict[task["hash_id"]] = task
                
        return task_dict


    except redis_exceptions.ResponseError as e:

        logging.error("Error on get_service_task")
        logging.error(e.args)
        logging.error(e)

        return None


# returns all task from specific service:
def get_service_tasks(r,service,status_code=None) -> Union[dict,None]:
    '''
    Return current tasks filter by service
    
    Parameters:
    - r (StrictRedis): object with connection details to a redis database
    - service (str): service of tasks to return
    - status_code (str) (optional): status code of the tasks to return

    Returns:
    - list of tasks, None if there was an error

    '''

    task_dict = {}

    try:
        # changed use of keys for hscan, since keys has bad performance in big data sets
        # task_list = r.keys("task_*")
        # scan_iter iterates between matching keys


        for task_id in r.scan_iter(match="task_*"):

            # get service key value from task_id dict key
            # serv = r.hget(task_id,"service")
            # changed since now is a serialized string, after python redis==3.x

            # skip if the service specified in the task_id is different
            tService = key_parts(task_id.decode('latin-1'))["service"]
            if tService is None or tService != service:
                continue

            json_task = r.get(task_id)
            if json_task is None:
                continue
            # logging.info(json_task)
            # decode because redis stores it in Bytes not string
            task = json.loads(json_task.decode('latin-1'))


            try:
                serv = task["service"]
            except Exception as e:
                logging.error(type(e))
                continue

            # if service is the requested one
            if serv == service:

                # if status_code is required to be filtered
                if status_code != None:
                    # if the status doesn't match the list, then is skipped
                    if task["status"] not in status_code:
                        continue

                task_dict[task["hash_id"]] = task

        return task_dict


    except redis_exceptions.ResponseError as e:

        logging.error("Error on get_service_task")
        logging.error(e.args)
        logging.error(e)

        return None