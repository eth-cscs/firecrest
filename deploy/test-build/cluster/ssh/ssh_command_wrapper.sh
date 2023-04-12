#!/bin/bash
##
##  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##

# Required OpenSSH >= 7.2 for ssh-keygen to read from stdin
# Optional OpenSSH >= 7.6 for direct access to certificates (via ExposeAuthInfo)

# trimmed full line returned by ssh-keygen (varies with versions)
CA_signature="Signing CA: ED25519 SHA256:Nmtm5cKY+X78KBkVSPqabLP7uNzOXiEshtkK/8XSTLs"

# user must be able to write
log_file=/tmp/firecrest-ssh-$UID.log

SOC="${SSH_ORIGINAL_COMMAND}"

set -u -e  # -e (abort on command error),  -u (undefined var are errors), -o pipefail (pipe errors)

# msg="$(date +%Y-%m-%dT%H:%M:%S) - "${UID}" -"
msg="FirecREST command execution user $USER ($UID) -"

cert_type=${SOC%%-cert-v01@openssh.com *}    # remove all after first space

case "$cert_type" in
  ssh-ecdsa|ssh-ecdsa-sk|ssh-ed25519|ssh-ed25519-sk|ssh-rsa)
    tmp1=$(ssh-keygen -Lf - <<< "${SOC}")
    tmp2=$(grep "^ *${CA_signature}" <<< "$tmp1")
    sig="Signing CA:"${tmp2## *Signing CA:} # remove left spaces
    if [ "$sig" != "$CA_signature" ]; then
      logger -p user.error "${msg} error - Wrong CA: ${sig}"
      exit 118
    fi
    c=$(grep "^ *force-command " <<< "$tmp1")
    SSH_EXECUTE=${c#*force-command *} # remove " force-command " and spaces
    ;;
  *)
    logger -p user.error "${msg} error - Unknown certificate type: $cert_type"
    exit 118
    ;;
esac

if [ "${SSH_EXECUTE:0:3}" == "ID=" ]; then
  actual="${SSH_EXECUTE#* }"    # remove before first space
 else
   actual="${SSH_EXECUTE}"
fi

command="${actual%% *}"    # remove all after first space

case "$command" in
  cat|head|rm|touch|true)
    ;;
  timeout)
    # sintax: timeout number command options
    tmp1=${actual#* }  # remove after first space
    duration=${tmp1%% *}    # remove all after first space
    tmp2=${tmp1#* }
    command2=${tmp2%% *}   # remove options
    case "$command2" in
      base64|cat|chmod|chown|cp|curl|file|head|id|ln|ls|mkdir|mv|rm|sbatch|scontrol|sha256sum|squeue|stat|tail|touch)
        ;;
      rsvmgmt)
        # advance reservation command
        ;;
      *)
        logger -p user.error  "${msg} error - Unhandled timeout command: ${command2}"
        exit 118
        ;;
    esac
    ;;
  sacct|sbatch|scancel|scontrol|squeue)
    # valid Slurm commands
    ;;
  curl)
    # storage
    ;;
  *)
    logger -p user.error "${msg} error - Unhandled command: ${command}"
    exit 118
    ;;
esac

# all ok, log command
logger -p user.info "${msg} ok - ${SSH_EXECUTE}"

# execute command
eval ${SSH_EXECUTE}
