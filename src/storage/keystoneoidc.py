#
#  Copyright (c) 2019-2021, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
from keystoneauth1.identity import v3
from keystoneauth1 import session as keystonesession
from keystoneauth1 import exceptions as keystoneexception
from keystoneauth1.identity import V3OidcPassword

import logging
import requests
import os
from keystone import Keystone

log = logging.getLogger(__name__)

class KeystoneOIDC(Keystone):

    def __init__(self):
        self.OS_AUTH_URL             = os.environ.get("F7T_OS_AUTH_URL")
        self.OS_IDENTITY_PROVIDER    = os.environ.get("F7T_OS_IDENTITY_PROVIDER")
        self.OS_PROTOCOL             = os.environ.get("F7T_OS_PROTOCOL")
        self.OS_PROJECT_ID           = os.environ.get("F7T_OS_PROJECT_ID")
        self.OS_CLIENT_ID            = os.environ.get("F7T_OS_CLIENT_ID")
        self.OS_CLIENT_SECRET        = os.environ.get("F7T_OS_CLIENT_SECRET")
        self.OS_DISCOVERY_ENDPOINT   = os.environ.get("F7T_OS_DISCOVERY_ENDPOINT")

    # returns a valid token if username & password are valid keystone credentials
    def authenticate(self,username,password):

        try:

            auth = V3OidcPassword(auth_url=self.OS_AUTH_URL, identity_provider=self.OS_IDENTITY_PROVIDER, protocol=self.OS_PROTOCOL,
                                client_id=self.OS_CLIENT_ID, client_secret=self.OS_CLIENT_SECRET, discovery_endpoint=self.OS_DISCOVERY_ENDPOINT, 
                                username=username, password=password)



            sess = keystonesession.Session(auth=auth)
            try:

                log.info(sess.get_token())
            except AttributeError as e:
                log.info(e)
                log.info(e.args)


            auth = v3.token.Token(auth_url=self.OS_AUTH_URL, token=sess.get_token(), project_id=self.OS_PROJECT_ID)

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
    def is_token_valid(self,token):

        url = f"{self.OS_AUTH_URL}/auth/tokens"

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
