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

        # if last_task_id isn't set (and doesn't exist on disk), then
        # is created
        if not r.exists("last_task_id"):
            r.set("last_task_id",0)

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


#close connection from client
def close_connection(r):
    try:
        addr = r.client_list()[0]["addr"]
        return r.client_kill(addr)
    except Exception as e:
        logging.error("Error on close_connection")
        logging.error(e)
        return False


#returns last task id
def get_last_task_id(r):

    try:
        # returns None if not exists
        last_task_id=r.get("last_task_id")

        # included .decode('latin-1') because in Python3 redis stores data as bytes not as string.
        return last_task_id.decode('latin-1')
    except Exception as e:
        logging.error("Error on get_last_task_id")
        logging.error(e)
        return None

# incrementes task id by 1
def incr_last_task_id(r):
    try:
        r.incr("last_task_id",1)
        return get_last_task_id(r)
    except Exception as e:
        logging.error("Error on incr_last_task_id")
        logging.error(e)
        return None

# creates last_task_id in redis:
def create_last_task_id(r):
    try:
        logging.info("Try to create 'last_task_id'")
        if get_last_task_id(r) == None:
            logging.info("'last_task_id' not created")
            r.set("last_task_id",1)
        return True
    except Exception as e:
        logging.error("Error on create_last_task_id")
        logging.error(e)
        return False


# save task status in redis server
# if success, returns True, otherwise, False
# task is the result of AsynkTask.get_status(), that's a dictionary with all fields
def save_task(r,id,task):

    task_id = "task_{id}".format(id=id)
    # mapping = {"status":status, "user":user, "data":data}
    logging.info("save_task {task_id} in REDIS".format(task_id=task_id))
    # logging.info(task)

    try:
        # serialize json from task:

        jtask = json.dumps(task)

        r.set(task_id,jtask)

        return True
    except Exception as e:
        logging.error(e)
        logging.error(type(e))
        return False


# set task expiration
def set_expire_task(r,id,secs):
    task_id = "task_{id}".format(id=id)
    try:
        # change to expire, because delete mantain deleted keys in redis
        # and iterate over them
        # r.delete(task_id)
        # redis.expire (key, seconds_to_live_from_now)
        r.expire(task_id,secs)
        return True
    except Exception as e:
        logging.error("Error on del_task")
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
def get_service_tasks(r,service):
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
                d = r.get(task_id)
                d = d.decode('latin-1')
                # if d is empty, task_id was removed
                # this should be fixed with r.expire
                # if len(d) == 0:
                #    continue

                task_dict[task_id] = d

        return task_dict


    except redis_exceptions.ResponseError as e:

        logging.error("Error on get_service_task")
        logging.error(e.args)
        logging.error(e)

        return None