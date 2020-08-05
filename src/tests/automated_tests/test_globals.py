import os

# name of user firing the tests:
#     will be TEST_USER for fake jwt, or service-account-{SA_CLIENT_ID} for sa login
CURRENT_USER = ""

if os.environ.get("F7T_SA_LOGIN", "").lower() != 'true':
    CURRENT_USER = os.environ.get("TEST_USER")
else:
    CURRENT_USER = 'service-account-' + os.environ.get("F7T_SA_CLIENT_ID")

USER_HOME = "/home/" + CURRENT_USER 

