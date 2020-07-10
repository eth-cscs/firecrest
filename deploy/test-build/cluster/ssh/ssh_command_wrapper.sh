#!/bin/bash
#
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#

# Required OpenSSH >= 7.2 for ssh-keygen to read from stdin
# Optional OpenSSH >= 7.6 for direct access to certificates (via ExposeAuthInfo)

# temp log dir
log_dir=/tmp

date >> ${log_dir}/ssh-original-$UID.txt
echo "${SSH_ORIGINAL_COMMAND}" >> ${log_dir}/ssh-original-$UID.txt

cert_type=${SSH_ORIGINAL_COMMAND%%-cert-v01@openssh.com *}    # remove all after first space

case "$cert_type" in
  ssh-ecdsa|ssh-ecdsa-sk|ssh-ed25519|ssh-ed25519-sk|ssh-rsa)
    tmp=$(echo ${SSH_ORIGINAL_COMMAND} | ssh-keygen -Lf - | grep force-command)
    SSH_EXECUTE=${tmp#*force-command *} # remove " force-command " and any spaces
    echo "dentro de cert: ${SSH_EXECUTE}" >> ${log_dir}/ssh-original-$UID.txt
    ;;
  *)
    echo "Unknown certificate type" >> ${log_dir}/ssh-original-$UID.txt
    exit 1
    ;;
esac


command=${SSH_EXECUTE%% *}    # remove all after first space


case "$command" in
    base64|cat|mkdir|rm|touch|/bin/true)
        ;;
    timeout)
        # sintax: timeout number command options
        tmp1=${SSH_EXECUTE#* }   # remove after first space
        duration=${tmp1%% *}              # remove all after first space
        tmp2=${tmp1#* }
        command2=${tmp2%% *}   # remove options

        case "$command2" in
            base64|chmod|chown|cp|file|ln|ls|mkdir|mv|rm|stat|tail|touch|sbatch|squeue|scontrol|wget)
                ;;
            *)
                echo "Unhandled timeout command: ${SSH_EXECUTE}" >>  ${log_dir}/ssh-unhandled-timeout-$UID.txt
                ;;
        esac
        ;;
    sacct|sbatch|scancel|scontrol|squeue)
        # valid Slurm commands
        ;;
    wget)
        # from object storage
        ;;
    *)
        echo "Unhandled command: ${SSH_EXECUTE}" >>  ${log_dir}/ssh-unhandled-$UID.txt
        ;;
esac

# execute original command
eval ${SSH_EXECUTE}
