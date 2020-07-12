#!/bin/bash
#  Copyright (c) 2019-2020, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#

# Required OpenSSH >= 7.2 for ssh-keygen to read from stdin
# Optional OpenSSH >= 7.6 for direct access to certificates (via ExposeAuthInfo)

# trimmed full line returned by ssh-keygen (varies with versions)
CA_signature="Signing CA: RSA SHA256:pTvMZwI/8nt6nv9ms/0Sao1F7b2JLGfV5lXYE8ERikI"

# user must be able to write
log_file=/tmp/firecrest-ssh-$UID.log

SOC="${SSH_ORIGINAL_COMMAND}"

#set -eu  # -e (abort on command error),  -u (undefined var are errors), -o pipefail (pipe errors)

date >> ${log_file}
echo "${SOC}" >> ${log_file}

cert_type=${SOC%%-cert-v01@openssh.com *}    # remove all after first space

case "$cert_type" in
  ssh-ecdsa|ssh-ecdsa-sk|ssh-ed25519|ssh-ed25519-sk|ssh-rsa)
    tmp1=$(ssh-keygen -Lf - <<< "${SOC}")
    tmp2=$(grep "^ *${CA_signature}" <<< "$tmp1")
    sig="Signing CA:"${tmp2## *Signing CA:} # remove left spaces
    if [ "$sig" != "$CA_signature" ]; then 
      echo "Wrong CA: ${sig}" >> ${log_file}
      exit 1;
    fi
    c=$(grep "^ *force-command " <<< "$tmp1")
    SSH_EXECUTE=${c#*force-command *} # remove " force-command " and any spaces
    echo "Cert command: ${SSH_EXECUTE}" >> ${log_file}
    ;;
  *)
    echo "Unknown certificate type" >> ${log_file}
    exit 1
    ;;
esac

command="${SSH_EXECUTE%% *}"    # remove all after first space

case "$command" in
    base64|cat|mkdir|rm|touch|/bin/true)
        ;;
    timeout)
        # sintax: timeout number command options
        tmp1=${SSH_EXECUTE#* }  # remove after first space
        duration=${tmp1%% *}    # remove all after first space
        tmp2=${tmp1#* }
        command2=${tmp2%% *}   # remove options
        case "$command2" in
            base64|chmod|chown|cp|file|ln|ls|mkdir|mv|rm|stat|tail|touch|sbatch|squeue|scontrol|wget)
                ;;
            *)
                echo "Unhandled timeout command: ${command2}" >> ${log_file}
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
        echo "Unhandled command: ${command}" >> ${log_file}
        ;;
esac

# execute command
eval ${SSH_EXECUTE}
