#!/bin/bash
##
##  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##

# read common variables
. ../../common/common.env

F7T_HTTP_SCHEMA="http"

if [ "${F7T_SSL_USE}" == "True" ]; then
    F7T_HTTP_SCHEMA="https"; 
fi

echo "F7T_HTTP_SCHEMA: $F7T_HTTP_SCHEMA"

# use '#' to separate string because '/' and ':' are valid on URLs
sed -e 's#F7T_AUTH_TOKEN_ISSUER#'${F7T_AUTH_TOKEN_ISSUER}'#' \
    -e 's#F7T_REALM_RSA_PUBLIC_KEY#'${F7T_REALM_RSA_PUBLIC_KEY}'#' \
    -e 's#F7T_COMPUTE_HOST#'${F7T_COMPUTE_HOST}'#' \
    -e 's#F7T_COMPUTE_PORT#'${F7T_COMPUTE_PORT}'#' \
    -e 's#F7T_STATUS_HOST#'${F7T_STATUS_HOST}'#' \
    -e 's#F7T_STATUS_PORT#'${F7T_STATUS_PORT}'#' \
    -e 's#F7T_STORAGE_HOST#'${F7T_STORAGE_HOST}'#' \
    -e 's#F7T_STORAGE_PORT#'${F7T_STORAGE_PORT}'#' \
    -e 's#F7T_TASKS_HOST#'${F7T_TASKS_HOST}'#' \
    -e 's#F7T_TASKS_PORT#'${F7T_TASKS_PORT}'#' \
    -e 's#F7T_UTILITIES_HOST#'${F7T_UTILITIES_HOST}'#' \
    -e 's#F7T_UTILITIES_PORT#'${F7T_UTILITIES_PORT}'#' \
    -e 's#F7T_HTTP_SCHEMA#'${F7T_HTTP_SCHEMA}'#' \
       < kong.yml.template > ../../kong/kong.yml 