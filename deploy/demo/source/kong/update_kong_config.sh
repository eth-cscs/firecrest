#!/bin/bash
##
##  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##

# read common variables
. ../../common/common.env

# use '#' to separate string because '/' and ':' are valid on URLs
sed -e 's#F7T_AUTH_TOKEN_ISSUER#'${F7T_AUTH_TOKEN_ISSUER}'#' \
    -e 's#F7T_REALM_RSA_PUBLIC_KEY#'${F7T_REALM_RSA_PUBLIC_KEY}'#' \
    -e 's#F7T_KONG_COMPUTE_URL#'${F7T_KONG_COMPUTE_URL}'#' \
    -e 's#F7T_KONG_STATUS_URL#'${F7T_KONG_STATUS_URL}'#' \
    -e 's#F7T_KONG_STORAGE_URL#'${F7T_KONG_STORAGE_URL}'#' \
    -e 's#F7T_KONG_TASKS_URL#'${F7T_KONG_TASKS_URL}'#' \
    -e 's#F7T_KONG_UTILITIES_URL#'${F7T_KONG_UTILITIES_URL}'#' \
       < kong.yml.template > ../../kong/kong.yml
