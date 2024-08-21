# SCHEDULERS PACKAGE

## Index
* [Abstract Class JobScheduler](#class-jobscheduler-abstract)
* [Class Job](#class-job)
* [Class JobScript](#class-jobscript)
* [Implementation Class SlurmScheduler](#implementation-class-slurmscheduler)
* [Factory Scheduler Function](#factory-scheduler)
* [Usage](#usage)

****

## Class JobScheduler (abstract)
Extends Abstract Base class ABC

Abstract base class with methods for job scheduler's backends.

### Abstract methods:
#### submit
```python
def submit(self, 
    Job submission_spec
):
```
Returns command for job submission based on the submission_spec
##### parameter
* submission_spec instance of Job

#### script_template
```python
def script_template(
    self, 
    string id,
    JobSpec script_spec,
    string filename=None 
):
```
Returns job script based on the script_spec.
##### parameters
* id type string
* script_spec type string
* filename (optional)

#### extract_jobid
```python
def extract_jobid(
    self, 
    string output
):
```
Extracts job ID from the output of the submission command.
##### parameter
* output

#### is_jobid
```python
def is_jobid(
    self, 
    string jobid_str
):
```
Checks if the string is a valid job ID for the scheduler
##### parameter
* jobid_str

#### job_info
```python
def job_info(
    self, 
    string jobid
):
```
Returns a command that will return the following information about the job:
* Job output filename
* Job error filename
* Job script filename
##### parameter:
* jobid

#### parse_job_result
```python
def parse_job_info(
    self, 
    dict output
):
```
Returns the following information about the job from the job_info command:
* Job output filename
* Job error filename
* Job script filename
##### parameter:
* output

#### cancel
Cancel all jobs listed in the job ID list parameter.
```python
def cancel(
    self, 
    string [] jobids
):
```
##### parameter:
* jobids: list of strings.

#### parse_cancel
```python
def parse_cancel_output(
        self, 
        string output):
```
##### parameter:
* output

#### poll
```python
def poll(
    self, 
    string user, 
    string jobids=None
):
```
Poll for active jobs. It is meant to return only the jobs of the user.
##### parameter:
* jobids
default: None

#### parse_poll_output
```python
def parse_poll_output(self):
```
Parses the poll command output.

#### accounting
```python
def accounting(
    self, 
    string username=None,
    string jobids=None, 
    string start_time=None, 
    string end_time=None
):
```
##### parameters:
* username
* jobids
* start_time
* end_time

#### parse_accounting_output
```python
def parse_accounting_output(
    self, 
    string output
):
```
Parses the accounting command output.
##### parameter
* output

#### check_job_time
```python
def check_job_time(
    string job_time
):
```
This method tries to parse correctly the time format from the *job_time* input parameter.
##### parameter
* *job_time* is a string with the timestap form the job.

**********

## Class Job
Class with submission specification.
Example of instance from *compute* module
```python
spec = Job(
    job_file['filename'], 
    job_dir, 
    account, 
    additional_options=plugin_options, 
    job_env=job_env
)
```

#### constructor
```python
def __init__(
    self, 
    dict job_script, 
    string job_dir, 
    string account=None, 
    dict job_env=None, 
    string [] additional_options=None
):
```
##### parameters:
* *job_script*: dictionary describing the job to be executed by the scheduler. Format of the dictionary:
```python
{
    'filename': string file name
    'content': string content of the job script to be run
}
```
* *job_dir*: string with the path of the job to launch.
* *account*: string with the username that own the job.
* *job_env*: dictionary with the environment variable list (example: {"var1": "value1", "var2": "value2"})
* *additional_options*: list of strings to provide more parameters to the scheduler.

#### attributes
* job_dir = job_dir
* job_script = job_script
* account = account
* job_env = job_env
* opts = additional_options if additional_options else []

**********
## Class JobScript
Class with script specifications. The constructor method initialize the instance's attributes that can be freely accessed.
#### constructor
```python
def __init__(
    self,
    string name,
    string time,
    string partition,
    string command,
    string dependency_id=None,
    string account=None,
    string constraint=None,
    dict job_env=None
):
```
##### parameters
* *name*: string type defining the name of the script.
* *time*: string type with the timestamp for the creation of the script.
* *partition*: string type selecting the partition where the job will run.
* *command*: string type specifying commands to be passed to the scheduler (e.g. to `srun -n`).
* *dependency_id*: string to specify the dependency rule for another job. A common implementation require that the job pointed by this ID should be successfully completed, before start the current one. Default None, meaning: no dependency.
* *account*: string to specify account used to access resourced within the running job. Default None.
* *constraint*: string type defining node features to assign the job. Default None.
* *job_env*: dictionary with a list of variables to include in the environment of the job. Example: {"var1": "value1", "var2": "value2"}. Default None.

**********
## Implementation Class SlurmScheduler
Extends JobScheduler
Slurm implementation of the abstract class Scheduler.

#### constructor
```python
def __init__(
    self, 
    string [] global_submission_opts=None
):
```
##### parameters
* *global_submission_opts*: list of string parameters to be passed to the `sbatch` command through command line in the [submit](#submit) method. The list is stored in the class attribute *_opts*. Default value: empty list.

#### submit (*overridden*)
```python
def submit(
    self, 
    Job submission_spec
):
return string
```
Returns the command to submit a job to Slurm using `sbatch`.
##### parameters
* *submission_spec*: instance of class [Job](#class-job) containing account, plugins and environment information for the `sbatch` command.
The attributes of the job class to be used 
An example composing the sbatch command is the following, the attributes of Job object are used to fill the command line arguments of the command.
```python
    cmd = ["sbatch"]
    cmd.append(f"--account='{submission_spec.account}'")
    cmd.append(f"--export='{submission_spec.job_env}'")
    cmd += [f"--chdir='{submission_spec.job_dir}'"]
    cmd += self._opts
    cmd += submission_spec.opts
    cmd += ["--", f"'{submission_spec.job_script}'"]
```

#### script_template (*overridden*)
```python
def script_template(self, 
    string id, 
    JobScript script_spec
):
return string
```
This method creates a Slurm job script using a template customized with the attributes of the script_spec object. 
The script can be run using `sbatch`.
##### parameters
* *id* string to identify the job
* *script_spec* instance of the [JobScript](#class-jobscript) class with the specification parameters of the script. Example of usage:
```python
script = (
    f"#! /bin/bash -l\n"
    f"#SBATCH --job-name='{script_spec.name}'\n"
    f"#SBATCH --time={script_spec.time}\n"
    f"#SBATCH --error=job-%j.err\n"
    f"#SBATCH --output=job-%j.out\n"
    f"#SBATCH --ntasks=1\n"
    f"#SBATCH --partition={script_spec.partition}\n"
    f"#SBATCH --constraint='{script_spec.constraint}'\n"
    f"#SBATCH --dependency=afterok:{script_spec.dependency_id}\n"
    f"#SBATCH --account='{script_spec.account}'\n"
    f"\n"
    f"echo Trace ID: {id}\n"
    f'echo -e "$SLURM_JOB_NAME started on $(date)"\n'
    f"srun -n $SLURM_NTASKS {script_spec.command}\n"
    f'echo -e "$SLURM_JOB_NAME finished on $(date)"\n'
)
```

#### extract_jobid (*overridden*)
```python
def extract_jobid(
    self, 
    string output
):
return string
```
This method extracts the job ID from the `sbatch` output and returns it.
##### parameter
* *output* string provided by the scheduler to be parsed extracting the job ID.

#### is_jobid (*overridden*)
```python
def is_jobid(
    self, 
    string jobid_str
):
return string
```
A valid Slurm job ID can have the form:
* `<job_id>` : where job_id is an integer
* `<het_job_id>+<het_job_offset>` : where `<het_job_id>` and `<het_job_offset>` are integers (for heterogeneous jobs)
* `<job_id>_<array_task_id>` : where `<job_id>` and `<array_task_id>` are integers (for job arrays)
* `<job_id>_[<array_task_id_start>-<array_task_id_end>]` : where `<job_id>`, `<array_task_id_start>` and `<array_task_id_end>` are integers (for job arrays)
* *jobid_str* string type to be validated using the rules listed above.

#### job_info (*overridden*)
```python
def job_info(
    self, 
    string jobid
):
return string
```
Returns the command to get information about the specified job ID in Slurm, 
using the command `scontrol -o show job='{jobid}`.
#### parameters
* *jobid*: string with a valid Job ID.

#### parse_job_info (*overridden*)
```python
def parse_job_info(
    self, 
    dict output
):
return dict
```
Parse the `scontrol` output to return a dictionary of key-value pairs with the data.
#### parameters
* *output* dictionary of string-string with the information parsed from the output of `scontrol`.

#### cancel (*overridden*)
```python
def cancel(
    self,
    string [] jobids
):
return string
```
This method prepares the call to `scancel -v` to cancel a list of jobs identified by their ID.
##### parameter
* *jobids* is a list of job ID strings.

#### parse_cancel_output (*overridden*)
```python
def parse_cancel_output(
    self,
    string output
):
return string|None
```
Parse the output of `scancel` detecting error messages. If an error is detected, a related message is returned. If no 
error was detected, then None is returned.
##### parameter
* *output* string from `scancel`call.

#### poll (*overridden*)
```python
def poll(
    self, 
    string user, 
    string jobids=None
):
return string
```
Poll method prepares the command to retrieve information on the running jobs, or on a specified job ID using `squeue`. 
In both cases, user shall be specified.
The following parameters are requested to `squeue`:
* `%i`  Job or job step id.
* `%P`  Partition of the job or job step.
* `%j`  Job or job step name.
* `%u`  User name for a job or job step.
* `%T`  Job  state  in extended form.
* `%S`  Actual  or expected start time of the job or job step.
* `%M`  Time used by the job or job step.
* `%L`  Time  left for the job to execute.
* `%D`  Number of nodes allocated to the job or the minimum number of nodes required by a pending job.
* `%R`  Allocated nodes/reason for pending/explanation for failure.
##### parameters
* *user* string with the name of the user owning the jobs.
* *jobids* optional string ti specify a particular job ID to be checked.

#### parse_poll_output (*overridden*)
```python
def parse_poll_output(
    self, 
    string output
):
return dict []
```
This method parses the output of `squeue` (instructed by the *poll* method) and returns a list of string-string 
dictionaries with the following keys:
* jobid
* partition
* name
* user
* state
* start_time
* time
* time_left
* nodes
* nodelist
#### parameters
* *output* the string result of `squeue`

#### accounting (*overridden*)
```python
def accounting(
    self, 
    string username=None, 
    string jobids=None, 
    string start_time=None, 
    string end_time=None
):
return string
```
This method prepares a the call `sacct -X` to extract the accounting information specified within the parameters. 
The reported data are:
* jobid 
* partition
* jobname 
* user
* state
* start
* cputime
* end
* NNodes
* NodeList
* ExitCode
* elapsed
#### parameters
* *username* string to restrict the query to a specified user.
* *jobids* string to restrict the query to a specific job ID.
* *start_time* string to restrict the query to a specific start timestamp.
* *end_time* string to restrict the query to a specific end timestamp.

#### parse_accounting_output (*overridden*)
```python
def parse_accounting_output(
    self, 
    string output
):
return dict []
```
This method parses the output of `sacct` (instructed by the *accounting* method) and extract a set of data for each 
entry read, stored in a string-string dictionary with the following keys:
* jobid 
* partition
* jobname 
* user
* state
* start
* cputime
* end
* NNodes
* NodeList
* ExitCode
* elapsed
##### parameter
* *output* the string result of `sacct`

#### get_nodes (*overridden*)
```python
def get_nodes(
    self, 
    string [] nodenames=None
):
return string
```
Given a list of node names, this method prepares a command line based on `scontrol -a show -o nodes` to get the 
information from Slurm.
##### parameter
* *nodenames* list of strings with the names of the nodes.

#### parse_nodes_output (*overridden*)
```python
def parse_nodes_output(
    self, 
    string output
):
return list(dict)
```
The method parses the resulting output of `scontrol` (instructed by the *get_nodes* method) and returns a list of 
string-string dictionaries containing the following information about the nodes:
* NodeName
* ActiveFeatures
* Partitions
* State
##### parameter
* *output* output string of the `scontrol` command

#### check_job_time (*overridden*)
```python
def check_job_time(
    string job_time
):
return bool
```
This method tries to parse correctly the `HH:MM:SS` time format from the *job_time* input parameter. If the format is 
valid, *True* is returned, otherwise *False*. Accepted formats are: 
* MM MM:SS 
* HH:MM:SS 
* DD-HH 
* DD-HH:MM 
* DD-HH:MM:SS
##### parameter
* *job_time* is a string with the timestap form the job.

#### is_valid_accounting_time (*Slurm private*)
```python
def is_valid_accounting_time(
    self,
    string sacct_time
):
return bool
```
This method validates the *saccTime* string checking that contains a supported timestamp format. If the format is valid,
*True* is returned, otherwise *False*.
##### parameter
* *sacct_time* string representing a timestamp from `sacct` to be evaluated.

******

# Factory Scheduler
The *Schedulers* package implements a factory function to instantiate the Scheduler's object based on the scheduler's 
name. The function looks for the class inside the package matching with the parameter (see [usage section](#usage) 
for details). If the class is found an instance is returned, otherwise an exception is raised.
```python
def factory_scheduler(
    string scheduler_name
):
return Object
```
##### parameter
* *scheduler_name* string representing the name of the scheduler to be instantiated.

******
# Usage
The *compute* module instantiates the *SlurmScheduler* using the *factory_scheduler* function. 
Note that *storage* instantiates but using the *STORAGE_SCHEDULER* variable instead of *COMPUTE_SCHEDULER*.
```python
try:
    scheduler = factory_scheduler(COMPUTE_SCHEDULER)
    app.logger.info("Scheduler selected: {}".format(COMPUTE_SCHEDULER))
except Exception as ex:
    scheduler = None
    app.logger.exception(ex)
    app.logger.error("No scheduler was set.")

```
In both modules, the factory function is used to automatically load the scheduler's class and create the object, 
if any error occurs (or the scheduler class is not found) an exception is raised and handled to se the `scheduler` 
variable to None. The selection of the scheduler class is based on the value of the environment variables COMPUTE_SCHEDULER and 
STORAGE_SCHEDULER, as shown in the following code.
```python
COMPUTE_SCHEDULER = os.environ.get("F7T_COMPUTE_SCHEDULER", "Slurm")
STORAGE_SCHEDULER = os.environ.get("F7T_STORAGE_SCHEDULER", "Slurm")
```
To implement a new scheduler's class it is requested to edit the [factory function](#factory-scheduler) of the schedulers 
package, adding a `elif` statement to the function codes, using the argument to point to the desired scheduler and 
instantiating the new class that shall extend the JobScheduler abstract class.
An example is provided in the section describing the [Slurm's implementation](#implementation-class-slurmscheduler).

The statement in the [factory function](#factory-scheduler) may be modified as in the following example.
The value of the *COMPUTE_SCHEDULER* and *STORAGE_SCHEDULER* variables shall match the selection inside 
the factory function.
```python
if scheduler_name == "Slurm":
    from schedulers.slurm import SlurmScheduler
    return SlurmScheduler()
elif scheduler_name == "Customized":
    from schedulers.slurm import CustomizedScheduler
    return CustomizedScheduler()   
raise Exception("Scheduler {} not supported".format(scheduler_name))
```