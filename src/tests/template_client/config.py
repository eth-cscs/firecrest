#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
class Config:
    '''Base configuration class for the Flask app'''
    

class DevConfig(Config):
    '''Class for development configuration'''
    DEBUG = True
    TESTING = True
    SECRET_KEY = b''
    OIDC_CLIENT_SECRETS = 'client_secrets.json'
    OIDC_ID_TOKEN_COOKIE_SECURE = False
    OIDC_REQUIRE_VERIFIED_EMAIL = False
    OIDC_USER_INFO_ENABLED = True
    OIDC_SCOPES = ['openid', 'email', 'profile']
    OIDC_INTROSPECTION_AUTH_METHOD = 'client_secret_post'
    FIRECREST_IP = ''
    MACHINES=['system01', 'system02']
    PARTITIONS={'system01':['part01','part02'], 'system02':['part01','part02','part03']}
    MICROSERVICES=['status', 'compute', 'utilities', 'storage', 'tasks']
    # machine for internal storage jobs, must be defined in MACHINES
    STORAGE_JOBS_MACHINE='cluster'
    HOME_DIR = '/home'
    CLIENT_PORT = 5000
