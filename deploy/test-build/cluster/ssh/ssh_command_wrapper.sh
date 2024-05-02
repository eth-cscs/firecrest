#!/bin/bash
##
##  Copyright (c) 2019-2024, ETH Zurich. All rights reserved.
##
##  Please, refer to the LICENSE file in the root directory.
##  SPDX-License-Identifier: BSD-3-Clause
##

# Required OpenSSH >= 7.2 for ssh-keygen to read from stdin
# Optional OpenSSH >= 7.6 for direct access to certificates (via ExposeAuthInfo)

SOC="${SSH_ORIGINAL_COMMAND}"
set -u  # -e (abort on command error),  -u (undefined var are errors), -o pipefail (pipe errors)
msg="FirecREST command execution user $USER ($UID) -"

c=$(ssh-keygen -Lf - <<< "${SOC}" | grep "^ *force-command ")

SSH_EXECUTE=${c#*force-command *} # remove " force-command " and spaces

if [ "${SSH_EXECUTE:0:3}" == "ID=" -o "${SSH_EXECUTE:0:6}" == "F7TID=" ]; then
  actual="${SSH_EXECUTE#* }"    # remove before first space
 else
  actual="${SSH_EXECUTE}"
fi

# Remove the SLURM_TIME_FORMAT=standard prefix if present
if [[ "${actual:0:26}" == "SLURM_TIME_FORMAT=standard" ]]; then
  actual="${actual#* }"    # remove everything before the first space, including the space
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
      base64|cat|chmod|chown|cp|curl|file|head|id|ln|ls|mkdir|mv|rm|sacct|sbatch|scancel|scontrol|sha256sum|squeue|stat|tail|touch|tar|unzip)
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
