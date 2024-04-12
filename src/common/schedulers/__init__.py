#
#  Copyright (c) 2019-2023, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import abc


class Job:
    """Class with submission specifications
    """

    def __init__(self, job_script, job_dir, account=None, env_file=None, additional_options=None):
        self.job_dir = job_dir
        self.job_script = job_script
        self.account = account
        self.env_file = env_file
        self.opts = additional_options if additional_options else []


class JobScript:
    """Class with script specifications
    """

    def __init__(
        self,
        name,
        time,
        partition,
        command,
        dependency_id=None,
        account=None,
        constraint=None,
        env_file=None
    ):
        self.name = name
        self.time = time
        self.partition = partition
        self.command = command
        self.dependency_id = dependency_id
        self.account = account
        self.constraint = constraint
        self.env_file = env_file


class JobScheduler(abc.ABC):
    """Abstract base class for job scheduler backends.
    """

    @abc.abstractmethod
    def submit(self, submission_spec):
        """Return command for job submission based on the submission_spec.
        """
        pass

    @abc.abstractmethod
    def script_template(self, filename, id, script_spec):
        """Return job script based on the script_spec.
        """
        pass

    @abc.abstractmethod
    def extract_jobid(self, output):
        """Extract jobid from the output of the submission command.
        """
        pass

    @abc.abstractmethod
    def is_jobid(self, jobid_str):
        """Check if the string is a valid job ID for the scheduler
        """
        pass

    @abc.abstractmethod
    def job_info(self, jobid):
        """Return a command that will return the following information about
        the job:
        * Job output filename
        * Job error filename
        * Job script filename
        """
        pass

    @abc.abstractmethod
    def parse_job_info(self, output):
        """Return the following information about
        the job from the job_info command:
        * Job output filename
        * Job error filename
        * Job script filename
        """
        pass

    @abc.abstractmethod
    def cancel(self, jobids):
        """Return command for job cancellation.
        """

    @abc.abstractmethod
    def parse_cancel_output(self, output):
        """Parse cancel command output for errors that are not caught by the
        error code and returns the appropriate error message.
        """

    @abc.abstractmethod
    def poll(self, user, jobids=None):
        """Poll for active jobs. It is meant to return only the jobs of the
        user.
        """
        pass

    @abc.abstractmethod
    def parse_poll_output(self):
        """Parse the poll command output.
        """
        pass

    @abc.abstractmethod
    def accounting(self, username=None, jobids=None, start_time=None, end_time=None):
        """Poll for jobs from a database.
        """
        pass

    @abc.abstractmethod
    def parse_accounting_output(self, output):
        """Parses the accounting command output.
        """
        pass

    @abc.abstractmethod
    def get_nodes(self, nodenames):
        """Return the compute nodes of the system.
        """
        pass

    @abc.abstractmethod
    def parse_nodes_output(self, output):
        """Parses the nodes command. Should return records with:
        * NodeName
        * ActiveFeatures
        * Partitions
        * State"
        """
        pass

    @abc.abstractmethod
    def get_partitions(self, partitions):
        """Return the partitions command of the system.
        """
        pass

    @abc.abstractmethod
    def parse_partitions_output(self, output):
        """Parses the partitions command. Should return records with:
        * PartitionName
        * State
        * TotalCPUS
        * TotalNodes
        * Default
        """
        pass

    @abc.abstractmethod
    def get_reservations(self, reservations):
        """Return the reservations command of the system.
        """
        pass

    @abc.abstractmethod
    def parse_reservations_output(self, output):
        """Parses the reservations command. Should return records with:
        * ReservationName
        * State
        * Nodes
        * TotalCPUS
        * TotalNodes
        * StartTime
        * EndTime
        """
        pass
