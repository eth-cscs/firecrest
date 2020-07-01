import os
from pytest_cases import fixture_plus

# name of user firing the tests:
#     will be TEST_USER for fake jwt, or service-account-{SA_CLIENT_ID} for sa login
CURRENT_USER = ""

if os.environ.get("F7T_SA_LOGIN", "").lower() != 'true':
    CURRENT_USER = os.environ.get("TEST_USER")
else:
    CURRENT_USER = 'service-account-' + os.environ.get("F7T_SA_CLIENT_ID")

USER_HOME = "/home/" + CURRENT_USER 

# return headers constructed in conftest.py
@fixture_plus
def headers(headers):
    return headers

@fixture_plus
def headers_no_auth(headers_no_auth):
    return headers_no_auth


@fixture_plus
def headers_invalid_auth(headers_invalid_auth):
    return headers_invalid_auth
