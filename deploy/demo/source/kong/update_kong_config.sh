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
sed -e 's#AUTH_TOKEN_ISSUER#'${AUTH_TOKEN_ISSUER}'#' \
    -e 's#REALM_RSA_PUBLIC_KEY#'${REALM_RSA_PUBLIC_KEY}'#' \
    -e 's#KONG_COMPUTE_URL#'${KONG_COMPUTE_URL}'#' \
    -e 's#KONG_STATUS_URL#'${KONG_STATUS_URL}'#' \
    -e 's#KONG_STORAGE_URL#'${KONG_STORAGE_URL}'#' \
    -e 's#KONG_TASKS_URL#'${KONG_TASKS_URL}'#' \
    -e 's#KONG_UTILITIES_URL#'${KONG_UTILITIES_URL}'#' \
       < kong.yml.template > ../../kong/kong.yml
