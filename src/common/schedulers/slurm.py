#
#  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import datetime
import logging
import re
import schedulers


logger = logging.getLogger("compute")

# string to separate fields on squeue, avoid forbidden chars
SQUEUE_SEP = ".:."


class SlurmScheduler(schedulers.JobScheduler):
    def __init__(self, global_submission_opts=None):
        self._opts = global_submission_opts if global_submission_opts else []

    def submit(self, submission_spec):
        cmd = ["sbatch"]
        if submission_spec.account:
            cmd.append(f"--account='{submission_spec.account}'")

        cmd += [f"--chdir='{submission_spec.job_dir}'"]
        cmd += self._opts
        cmd += submission_spec.opts
        cmd += ["--", f"'{submission_spec.job_script}'"]

        return " ".join(cmd)

    def extract_jobid(self, output):
        if not output:
            return ""

        list_line = output.split()
        if not self.is_jobid(list_line[-1]):
            # For compatibility reasons if the jobid is not valid, we
            # return the original string
            return output

        # For compatibility with older versions we try to return integer,
        # even though valid jobids don't have to be integers.
        try:
            jobid = int(list_line[-1])
        except ValueError:
            jobid = list_line[-1]

        return jobid

    def is_jobid(self, jobid_str):
        """A valid Slurm job ID can have the form:
          * <job_id> : where job_id is an integer
          * <het_job_id>+<het_job_offset> : where <het_job_id> and <het_job_offset> are integers (for heterogeneous jobs)
          * <job_id>_<array_task_id> : where <job_id> and <array_task_id> are integers (for job arrays)
          * <job_id>_[<array_task_id_start>-<array_task_id_end>] : where <job_id>, <array_task_id_start> and <array_task_id_end> are integers (for job arrays)
        """
        jobid_pattern = r"\d+(?:\+\d+|_\d+|_\[\d+-\d+\])?"
        if re.fullmatch(jobid_pattern, jobid_str):
            return True
        else:
            logger.error(
                f"Wrong Slurm ID, the jobid {jobid_str} doesn't fit any of "
                f"the following patterns: <job_id> , "
                f"<het_job_id>+<het_job_offset> , <job_id>_<array_task_id> "
                f"or <job_id>_[<array_task_id_start>-<array_task_id_end>]"
            )
            return False

    def script_template(self, id, script_spec):
        script = (
            f"#! /bin/bash -l\n"
            f"#SBATCH --job-name='{script_spec.name}'\n"
            f"#SBATCH --time={script_spec.time}\n"
            f"#SBATCH --error=job-%j.err\n"
            f"#SBATCH --output=job-%j.out\n"
            f"#SBATCH --ntasks=1\n"
            f"#SBATCH --partition={script_spec.partition}\n"
        )
        if script_spec.dependency_id:
            script += f"#SBATCH --dependency=afterok:{script_spec.dependency_id}\n"

        if script_spec.account:
            script += f"#SBATCH --account='{script_spec.account}'\n"

        script += (
            f"\n"
            f"echo Trace ID: {id}\n"
            f'echo -e "$SLURM_JOB_NAME started on $(date)"\n'
            f"srun -n $SLURM_NTASKS {script_spec.command}\n"
            f'echo -e "$SLURM_JOB_NAME finished on $(date)"\n'
        )

        return script

    def job_info(self, jobid):
        return f"scontrol -o show job='{jobid}'"

    def parse_job_info(self, output):
        control_list = output.split()
        # Tokens are expected to be space-separated and with a k=v form.
        # See man scontrol show
        control_dict = {
            value.split("=")[0]: value.split("=")[1]
            for value in control_list
            if "=" in value
        }

        return control_dict

    def poll(self, user, jobids=None):
        # In Slurm we implement this with the squeue command
        cmd = ["squeue", f"--user={user}"]
        if jobids:
            cmd.append(f"--jobs='{','.join(jobids)}'")

        S = SQUEUE_SEP
        # %i  Job or job step id.
        # %P  Partition of the job or job step.
        # %j  Job or job step name.
        # %u  User name for a job or job step.
        # %T  Job  state  in extended form.
        # %S  Actual  or expected start time of the job or job step.
        # %M  Time used by the job or job step.
        # %L  Time  left for the job to execute.
        # %D  Number of nodes allocated to the job or the minimum number of
        #     nodes required by a pending job.
        # %R  Allocated nodes/reason for pending/explanation for failure.
        cmd += [
            f"--format='%i{S}%P{S}%j{S}%u{S}%T{S}%M{S}%S{S}%L{S}%D{S}%R'",
            "--noheader",
        ]
        return " ".join(cmd)

    def parse_poll_output(self, output):
        jobs = []
        for job_str in output.split("\n"):
            job_info = job_str.split(SQUEUE_SEP)
            jobs.append(
                {
                    "jobid": job_info[0],
                    "partition": job_info[1],
                    "name": job_info[2],
                    "user": job_info[3],
                    "state": job_info[4],
                    "start_time": job_info[5],
                    "time": job_info[6],
                    "time_left": job_info[7],
                    "nodes": job_info[8],
                    "nodelist": job_info[9],
                }
            )

        return jobs

    def accounting(self, username=None, jobids=None, start_time=None, end_time=None):
        cmd = ["sacct", "-X"]
        # -X so no step information is shown (ie: just jobname, not jobname.batch or jobname.0, etc)
        if username:
            cmd.append(f"--user={username}")

        if start_time:
            if self.is_valid_accounting_time(start_time):
                cmd.append(f"--starttime='{start_time}'")
            else:
                logger.warning(f"starttime wrongly encoded: {start_time}")

        if end_time:
            if self.is_valid_accounting_time(end_time):
                cmd.append(f"--endtime='{end_time}'")
            else:
                logger.warning(f"endtime wrongly encoded: {end_time}")

        if jobids:
            jobids_str = ",".join(jobids)
            cmd.append(f"--jobs='{jobids_str}'")

        # --parsable2 = limits with | character not ending with it
        cmd += [
            "--format='jobid,partition,jobname,user,state,start,cputime,end,NNodes,NodeList,ExitCode'",
            "--noheader",
            "--parsable2",
        ]

        return " ".join(cmd)

    def parse_accounting_output(self, output):
        jobs = []
        for job_str in output.split("\n"):
            job_info = job_str.split("|")
            jobs.append(
                {
                    "jobid": job_info[0],
                    "partition": job_info[1],
                    "name": job_info[2],
                    "user": job_info[3],
                    "state": job_info[4],
                    "start_time": job_info[5],
                    "time": job_info[6],
                    "time_left": job_info[7],
                    "nodes": job_info[8],
                    "nodelist": job_info[9],
                    "exit_code": job_info[10],
                }
            )

        return jobs

    def cancel(self, jobids):
        quoted_jobids = [f"'{j}'" for j in jobids]
        return f"scancel -v {','.join(quoted_jobids)}"

    def parse_cancel_output(self, output):
        # Scancel doesn't give an error code over invalid or completed jobs,
        # but with -v we can get if from stderr
        # FIXME we should return the error per jobid when we support
        # cancelling multiple jobs per request
        if "error" in output:
            err_msg = output[(output.index("error") + 7) :]
            return err_msg

        return None

    def is_valid_accounting_time(self,sacctTime):
        # HH:MM[:SS] [AM|PM]
        # MMDD[YY] or MM/DD[/YY] or MM.DD[.YY]
        # MM/DD[/YY]-HH:MM[:SS]
        # YYYY-MM-DD[THH:MM[:SS]]

        if "/" in sacctTime:

            try:
                # try: MM/DD
                datetime.datetime.strptime(sacctTime, "%m/%d")
                # try: MM/DD/YY
                datetime.datetime.strptime(sacctTime, "%m/%d/%y")
                # try: MM/DD-HH:MM
                datetime.datetime.strptime(sacctTime, "%m/%d-%H:%M")
                # try: MM/DD-HH:MM:SS
                datetime.datetime.strptime(sacctTime, "%m/%d-%H:%M:%S")
                # try: MM/DD/YY-HH:MM
                datetime.datetime.strptime(sacctTime, "%m/%d/%y-%H:%M")
                # try: MM/DD/YY-HH:MM:SS
                datetime.datetime.strptime(sacctTime, "%m/%d/%y-%H:%M:%S")

                return True
            except ValueError as e:
                logger.error(e, exc_info=True)
                return False

        if ":" in sacctTime:

            try:
                # try: HH:MM
                datetime.datetime.strptime(sacctTime, "%H:%M")
                # try: HH:MM:SS
                datetime.datetime.strptime(sacctTime, "%H:%M:%S")
                # try: HH:MM:SS AM|PM
                datetime.datetime.strptime(sacctTime, "%H:%M:%S %p")
                # try: YYYY-MM-DDTHH:MM
                datetime.datetime.strptime(sacctTime, "%Y-%m-%dT%H:%M")
                # try: YYYY-MM-DDTHH:MM:SS
                datetime.datetime.strptime(sacctTime, "%Y-%m-%dT%H:%M:%S")
                return True
            except ValueError as e:
                logger.error(e, exc_info=True)
                return False

        if "." in sacctTime:
            try:
                # try: MM.DD
                datetime.datetime.strptime(sacctTime, "%m.%d")
                # try: MM.DD.YY
                datetime.datetime.strptime(sacctTime, "%m.%d.%y")
                return True
            except ValueError as e:
                logger.error(e, exc_info=True)
                return False

        if "-" not in sacctTime:
            try:
                # try: MMDD
                datetime.datetime.strptime(sacctTime, "%m%d")
                # try: MMDDYY
                datetime.datetime.strptime(sacctTime, "%m%d%y")
                return True
            except ValueError as e:
                logger.error(e, exc_info=True)
                return False

        try:
            # try: YYYY-MM-DD
            datetime.datetime.strptime(sacctTime, "%Y-%m-%d")
            return True
        except ValueError as e:
            logger.error(e, exc_info=True)
            return False

    def check_job_time(jobTime):
        # try to parse correctly the HH:MM:SS time format
        # acceptable formats are: MM MM:SS HH:MM:SS DD-HH DD-HH:MM DD-HH:MM:SS
        # time.strptime("15:02","%H:%M")

        if ":" not in jobTime and "-" not in jobTime:
            # asumes is just minutes:
            try:
                mm = int(jobTime)  # exception stands for ValueError int convertion

                if mm < 1:  # if minutes smaller than 1
                    return False

            except ValueError as ve:
                logger.error(ve, exc_info=True)
                return False

            return True

        if ":" not in jobTime and "-" in jobTime:
            # asumes is DD-HH
            try:
                [dd, hh] = jobTime.split("-")

                dd = int(dd)  # exception stands for ValueError int convertion
                hh = int(hh)

                if (
                    hh < 0 or hh > 23
                ):  # if hours is bigger than one day hour or smaller than 0
                    return False

                if dd < 0:
                    return False

            except Exception as e:
                logger.error(e, exc_info=True)
                return False

            return True

        if ":" in jobTime and "-" not in jobTime:
            # asumes is HH:MM:SS or MM:SS

            splittedJobTime = jobTime.split(":")

            if len(splittedJobTime) == 2:
                # MM:SS
                [mm, ss] = splittedJobTime

                try:
                    mm = int(mm)
                    ss = int(ss)

                    if mm < 0:
                        return False
                    if ss < 0 or ss > 59:
                        return False
                except Exception as e:
                    logger.error(e, exc_info=True)
                    return False

                return True

            if len(splittedJobTime) == 3:
                # HH:MM:SS

                [hh, mm, ss] = splittedJobTime

                try:
                    hh = int(hh)
                    mm = int(mm)
                    ss = int(ss)

                    if hh < 0:
                        return False

                    if mm < 0 or mm > 59:
                        return False
                    if ss < 0 or ss > 59:
                        return False
                except Exception as e:
                    logger.error(e, exc_info=True)
                    return False

                return True

            return False

        # last assumed option is jobTime with - and : --> DD-HH:MM or DD-HH:MM:SS

        try:
            [dd, rest] = jobTime.split("-")

            dd = int(dd)
            if dd < 0:
                return False

            splittedJobTime = rest.split(":")

            if len(splittedJobTime) == 2:
                # MM:SS
                [mm, ss] = splittedJobTime

                try:
                    mm = int(mm)
                    ss = int(ss)

                    if mm < 0:
                        return False
                    if ss < 0 or ss > 59:
                        return False
                except Exception as e:
                    logger.error(e, exc_info=True)
                    return False

                return True

            if len(splittedJobTime) == 3:
                # HH:MM:SS

                [hh, mm, ss] = splittedJobTime

                try:
                    hh = int(hh)
                    mm = int(mm)
                    ss = int(ss)

                    if hh < 0:
                        return False

                    if mm < 0 or mm > 59:
                        return False
                    if ss < 0 or ss > 59:
                        return False
                except Exception as e:
                    logger.error(e, exc_info=True)
                    return False

                return True

            return False

        except Exception as e:
            logger.error(e, exc_info=True)

            return False
