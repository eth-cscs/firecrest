#!/bin/bash

# temp log dir
log_dir=/tmp

date >> ${log_dir}/ssh-original-$UID.txt
echo "${SSH_ORIGINAL_COMMAND}" >> ${log_dir}/ssh-original-$UID.txt

command=${SSH_ORIGINAL_COMMAND%% *}    # remove all after first space

case "$command" in
    cat|mkdir|rm|touch)
        ;;
    timeout)
        # sintax: timeout number command optins
        tmp1=${SSH_ORIGINAL_COMMAND#* }   # remove after first space
        duration=${tmp1%% *}              # remove all after first space
        tmp2=${tmp1#* }
        command2=${tmp2%% *}   # remove options

        case "$command2" in
            chmod|chown|cp|file|ln|ls|mkdir|mv|rm|stat|tail|touch|sbatch|squeue|scontrol|wget)
                ;;
            *)
                echo "Unhandled timeout command: ${SSH_ORIGINAL_COMMAND}" >>  ${log_dir}/ssh-unhandled-timeout-$UID.txt
                ;;
        esac
        ;;
    sacct|sbatch|scancel|scontrol|squeue)
        # valid Slurm commands
        ;;
    wget)
        # from object storage
        ;;
    /usr/libexec/openssh/sftp-server)
        # SFTP transfer
        ;;
    *)
        echo "Unhandled command: ${SSH_ORIGINAL_COMMAND}" >>  ${log_dir}/ssh-unhandled-$UID.txt
        ;;
esac

# execute original command
eval ${SSH_ORIGINAL_COMMAND}
