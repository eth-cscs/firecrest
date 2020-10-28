#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import redis
import redis.exceptions as redis_exceptions
import logging
import json

# create redis server connection, and return StrictRedis object
# otherwise returns None
def create_connection(host,port,passwd="",db=0):

    logging.info("Trying to start taskpersistance connection")
    logging.info("Host: {}".format(host))

    try:
        r = redis.StrictRedis(host=host,port=port,db=db,password=passwd)
        # r = Redis(host=host, port=port, db=db, password=passwd)
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


# incrementes task id by 1
def incr_last_task_id(r):
    try:
        return r.incr("last_task_id",1)
    except Exception as e:
        logging.error("Error on incr_last_task_id")
        logging.error(e)
        return None

# save task status in redis server
# if success, returns True, otherwise, False
# task is the result of AsynkTask.get_status(), that's a dictionary with all fields
def save_task(r,id,task,exp_time=None):

    task_id = "task_{id}".format(id=id)
    # mapping = {"status":status, "user":user, "data":data}
    logging.info("save_task {task_id} in REDIS".format(task_id=task_id))    

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
def set_expire_task(r,id,secs):
    task_id = f"task_{id}"
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
def del_task(r,id):

    # use set_expire_task with 0 seconds
    # it's better than delete
    return set_expire_task(r, id, 0)


# return all task in dict format
def get_all_tasks(r):

    task_dict = {}

    try:
        # changed use of keys for hscan, since keys has bad performance in big data sets
        # task_list = r.keys("task_*")
        # scan returns: [cursor, [list of keys]]
        # task_list = r.scan(cursor=0, match="task_*")[1]

        for task_id in r.scan_iter(match="task_*"):


            # djson = r.hgetall(task_id)
            task_json = r.get(task_id)

            # decode because redis stores it in Bytes not string
            task_json = task_json.decode('latin-1')
            task_id = task_id.decode('latin-1')

            # if d is empty, task_id was removed
            # this should be fixed with r.expire
            # if len(d) == 0:
            #    continue
            d = json.loads(task_json)
            task_dict[task_id]=d

        return task_dict


    except Exception as e:
        logging.error("Error on get_all_tasks")
        logging.error(e)
        return None

# returns all task from specific service:
def get_service_tasks(r,service,status_code=None):
    task_dict = {}

    try:
        # changed use of keys for hscan, since keys has bad performance in big data sets
        # task_list = r.keys("task_*")
        # scan_iter iterates between matching keys


        for task_id in r.scan_iter(match="task_*"):

            # get service key value from task_id dict key
            # serv = r.hget(task_id,"service")
            # changed since now is a serialized string, after python redis==3.x

            json_task = r.get(task_id)
            # logging.info(json_task)
            # decode because redis stores it in Bytes not string
            task_id = task_id.decode('latin-1')
            #json_task = json_task.decode('latin-1')


            task = json.loads(json_task)


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

                d = r.get(task_id)
                d = d.decode('latin-1')
                
                task_dict[task_id] = d

        return task_dict


    except redis_exceptions.ResponseError as e:

        logging.error("Error on get_service_task")
        logging.error(e.args)
        logging.error(e)

        return None