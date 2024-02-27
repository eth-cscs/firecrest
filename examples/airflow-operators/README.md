# Airflow operator with FirecREST

[Apache Airflow](https://airflow.apache.org) is an open-source workflow management platform. Airflow uses directed acyclic graphs (DAGs) to manage the workflows. Tasks and dependencies are defined in Python and then Airflow takes care of the scheduling and execution. DAGs can be run either on a schedule or based on external event triggers.

For this tutorial we have defined an Airflow DAG combining small tasks which can run localy and compute-intensive tasks that must run on a supercomputer. Our goal is to add to Airflow the support for executing the DAG's compute-intensive tasks in Piz Daint via [FirecREST](https://firecrest.readthedocs.io). For that we are going to write [custom Airflow operators](https://airflow.apache.org/docs/apache-airflow/stable/howto/custom-operator.html) that will use FirecREST to access Piz Daint.

The idea behind this is very simple.
Operators are defined as units of work for Airflow to complete. Custom operators can be written by extending Airflow's [`BaseOperator`](https://airflow.apache.org/docs/apache-airflow/stable/_api/airflow/models/baseoperator/index.html#airflow.models.baseoperator.BaseOperatorMeta) class.
We only need to define the arguments specific to our logic and the `execute` function that will use [PyFirecrest](https://pyfirecrest.readthedocs.io/en/stable/) to submit the jobs as well as for transfering files to and from the HPC facilities.
Our operators will look something like this

```python
class FirecRESTCustomOperator(BaseOperator):
    def init(self, arg1, arg2, **kwargs):
        super().__init__(**kwargs)
        self.arg1 = arg1
        self.arg2 = arg2

    def execute(self, context):
        # pyfirecrest suff
```
If this was an operator to submit a job, `arg1` and `arg2` would be the name of the system (`daint`) and the batch script to submit a Slurm job.

## Setting up the credentials for PyFirecrest

We can export as environment variables the credentials that FirecREST will use and read them within our operators.

```bash
export FIRECREST_CLIENT_ID=<client-id>
export FIRECREST_CLIENT_SECRET=<client-secret>
export AUTH_TOKEN_URL=https://auth.cscs.ch/auth/realms/firecrest-clients/protocol/openid-connect/token
export FIRECREST_URL=https://firecrest.cscs.ch
```

## Installing Apache Airflow

We are going to run Airflow in our personal computers.
We recommend to install it on a virtual environment.
You just need to do the following:
```bash
python -m venv fc-training-env
. fc-training-env/bin/activate
pip install apache-airflow pyfirecrest
```

### Launching Airflow

Before launching Airflow, we need to initialize it's database
```bash
export AIRFLOW_HOME=$HOME/airflow-fc-training
airflow db init
```
Airflow comes with many examples that show up in the dashboard. You can set `load_examples = False` in your `$AIRFLOW_HOME/airflow.cfg` configuration file to start Airflow with a clean dashboard.

Let's launch Airflow in *standalone* mode (only suitable for developing/testing)
```bash
airflow standalone
```

When Airflow standalone starts, it creates an admin user and generates credentials to login in the dashboard at http://127.0.0.1:8080.
You can find them (username and password) by the end of the initialization message.
It looks like this:
```
standalone | Airflow is ready
standalone | Login with username: admin  password: <password>
standalone | Airflow Standalone is for development purposes only. Do not use this in production!
```

## Hands On

For this example we want to propose you the following problem:
Let's say that we have a simulation to find geometries of new crystal structures.
Anytime a geometry is produced we would like a Quantum Espresso calculation to be triggered to compute certain properties of it.
We have defined the Airflow DAG that will the do the work in the file [airflow-dag.py](airflow-dag.py). Its tasks are:
 - Detect that a new structure has been produced
 - Upload the structure and its pseudopotential to Piz Daint
 - Submit a job to Piz Daint to compute the properties
 - Download the output of the calculation
 - Log the relevant values from the output on a table
 - Delete the file with the structure

We have set this processes to be scheduled daily.

You must edit the [airflow-dag.py](airflow-dag.py) file and set `workdir` as the absolute path to the directory `airflow-operators` and `username` as your user name in Piz Daint.
For this example, we are going to simulate the creation of the new structure by coping the file `si.scf.in` to the `{workdir}/structs` directory.

To see the DAG on Airflow's dashboard we must copy the file to `$AIRFLOW_HOME/dags`:
```bash
mkdir $AIRFLOW_HOME/dags
cp airflow-dag.py $AIRFLOW_HOME/dags
```
It will show up with the name `firecrest_example` after some seconds / refreshing the page.

You can click on it and browse the different tabs such as *Graph*.
The execution of the DAG can be triggered by clicking on the *Play* button at the right hand side of the dashboard next to the tabs.

The file [firecrest_airflow_operators.py](firecrest_airflow_operators.py) has the implementation of the operators.

For Airflow to see our module, the file must be in the `$PYTHONPATH`. You can install it with
```bash
cd airflow-operators/
pip install .
```
