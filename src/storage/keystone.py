#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from keystoneauth1.identity import v3
from keystoneauth1 import session as keystonesession
from keystoneauth1 import exceptions as keystoneexception
from keystoneauth1.extras._saml2 import V3Saml2Password

import logging
import requests
import os


OS_AUTH_URL             = os.environ.get("F7T_OS_AUTH_URL")
OS_IDENTITY_PROVIDER    = os.environ.get("F7T_OS_IDENTITY_PROVIDER")
OS_IDENTITY_PROVIDER_URL= os.environ.get("F7T_OS_IDENTITY_PROVIDER_URL")
OS_PROTOCOL             = os.environ.get("F7T_OS_PROTOCOL")
OS_INTERFACE            = os.environ.get("F7T_OS_INTERFACE")
OS_PROJECT_ID           = os.environ.get("F7T_OS_PROJECT_ID")


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# returns a valid token if username & password are valid keystone credentials
def authenticate(username,password):

    try:

        auth = V3Saml2Password(auth_url=OS_AUTH_URL, identity_provider=OS_IDENTITY_PROVIDER, protocol=OS_PROTOCOL,
                               identity_provider_url=OS_IDENTITY_PROVIDER_URL, username=username, password=password)



        sess = keystonesession.Session(auth=auth)
        try:

            log.info(sess.get_token())
        except AttributeError as e:
            log.info(e)
            log.info(e.args)


        auth = v3.token.Token(auth_url=OS_AUTH_URL, token=sess.get_token(), project_id=OS_PROJECT_ID)

        sess = keystonesession.Session(auth=auth)

        OS_TOKEN = sess.get_token()

        return {"error":0,"OS_TOKEN":OS_TOKEN}

    except keystoneexception.http.BadRequest as e:
        log.error(e)
        log.error(e.message)
        log.error(e.details)
        return {"error":1,"msg":e.message}


    except Exception as e:

        log.error(type(e))
        return {"error":1,"msg":e}


# Checks if token is valid directly with keystone API
def is_token_valid(token):

    url = "{os_auth_url}/auth/tokens".format(os_auth_url=OS_AUTH_URL)

    headers = {"X-Auth-Token":token,
               "X-Subject-Token":token}

    try:

        r = requests.get(url=url,headers=headers)

        if r.status_code == 200:
            logging.info("Valid token")
            return True

        logging.warning("Invalid token")

        return False

    except requests.exceptions.RequestException as re:
        logging.error(re)
        logging.error("Invalid token request")
        return False
