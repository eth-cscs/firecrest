***** Install Pytest and dependencies *****

pip3 install -r requirements.txt



***** Configure Test environment *****

The environment variables for your test implementation must be configured 
in the pytest section of pytest.ini file.
For example, for "test-build" deploy, the configuration is as follows:

#-----------------------------------------------------------------------
[pytest]
env_override_existing_values = 1
env_files =
    test.env
    ../../../deploy/test-build/environment/common.env
    ../../../deploy/test-build/environment/storage.env
#-----------------------------------------------------------------------

Moreover, additional variables relative to testing need to be configured in test.env file:
For "test-build" deploy we have the following:

#----------------------------------------------------------------------------------------------
TEST_USER=testuser   # existing user name: will be encoded in the authorization JWT
FIRECREST_URL=        # It must be setted if microservices are accesed through a gateway like kong
HOST_NETWORK = True  # This must be setted to True if microservices are in a docker host network
#----------------------------------------------------------------------------------------------



***** Configure multiple Test environments *****

By default pytest will look for configurations in pytest.ini file.
For testing multiple deployments, it's recommended to create a custom .ini file
for each deployment. For example, for test-build you could create a "test-build.ini" file
which will look as follows:

#-----------------------------------------------------------------------
[pytest]
env_override_existing_values = 1
env_files =
    test-build.env
    ../../../deploy/test-build/environment/common.env
    ../../../deploy/test-build/environment/storage.env
#-----------------------------------------------------------------------

Note that testing environments variables are searched in "test-build.env" file,
which will be exactly the same as the test.env file shown in the previous example.



***** Run tests *****

Run all tests:
  $ pytest [-c custom_config.ini]

Run unit tests only:
  $ pytest -c test-build.ini unit/

Run integration tests only:
  $ pytest -c test-build.ini integration/

Run a specific test file:
  $ pytest [-c custom_config.ini] unit/test_unit_jobs.py

Run a specific test within a test file:
   $ pytest [-c custom_config.ini] unit/test_unit_jobs.py -k "test_submit_job or test_acct"



***** Tests Limitations *****

In order to test implementations that are behind a gateway with authetication 
you will need to disable token verification. This has to be done in your gateway configuration. 
Also you must set to empty the REALM_RSA_PUBLIC_KEY environment variable in the common.env file of your deploy.
Finally, you will need to specify the firecrest gateway address in FIRECREST_URL environment variable.


UPDATE - 04/20/2020

It's possible to test implementations behind a gateway using service account(SA) logins.
You need to setup the following environment variables:

# The gateway url
FIRECREST_URL = http://myapigateway

# enable login with SA
SA_LOGIN      = True 

# Openid service url
SA_TOKEN_URI  = http://myopenidservice/auth/realms/kcrealm/protocol/openid-connect/token

# The credentials for SA
# NOTE: the client must have enabled Service Accounts feature
SA_SECRET_KEY = mysecret
SA_CLIENT_ID  = myserviceaccount

The "demo" implementation has been configured to be tested using service account authentication.
Open demo.env file to check the configuration values that have been set.
As previously shown, run the tests on "demo" implementation by executing the following command:

    pytest -c demo.ini 


