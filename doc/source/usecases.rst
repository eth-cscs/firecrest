=================
Use-case examples
=================

In the code's repository you can find examples of use cases for FirecREST where `PyFirecREST <https://github.com/eth-cscs/pyfirecrest/>`__ is used as backend for web user interfaces and workflow automation tools that interact with remote high performance computing (HPC) facilities.


CI/CD pipeline
^^^^^^^^^^^^^^

In this `example <https://github.com/eth-cscs/firecrest/examples/CI-pipeline>`__ we create a GitHub CI/CD pipeline that will run in a HPC system through FirecREST. 

Web User Interfaces
^^^^^^^^^^^^^^^^^^^

We show examples of Web Graphic User Interface applications in Python that interact with HCP services using FirecREST.
Two workflows are used for the authentication with an identity provider: `the Client Credential workflow <https://github.com/eth-cscs/firecrest/examples/UI-client-credentials>`__ and `the Authorization Code workflow <https://github.com/eth-cscs/firecrest/examples/UI-code-flow>`__.

FirecREST Operators for Airflow
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In this `example <https://github.com/eth-cscs/firecrest/examples/UI-code-flow>`__ we define an Airflow graph combining small tasks which run localy in a laptop with compute-intensive tasks that must run on an HPC system. The idea is to add in Airflow the support for executing the compute-intensive tasks in a supercomputer via FirecREST. For that we are going to write custom Airflow operators that will use FirecREST to access the HPC system.

JupyterHub with FirecRESTSpawner
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This is a `tutorial <https://github.com/eth-cscs/firecrest/examples/jupyterhub>`__ on how to run `JupyterHub <https://jupyterhub.readthedocs.io/en/stable/>`__ with `FirecRESTSpawner <https://github.com/eth-cscs/firecrestspawner>`__ using the `Docker demo of FirecREST <https://github.com/eth-cscs/firecrest/tree/master/deploy/demo>`__.

FirecRESTSpawner is a tool for launching Jupyter Notebook servers from JupyterHub on HPC clusters through FirecREST.
It can be deployed on Kubernetes as part of JupyterHub and configured to target different systems.
In this tutorial, we will set up a simplified environment on a local machine, including a `Docker Compose <https://docs.docker.com/compose>`__ deployment of FirecREST, a single-node Slurm cluster and a `Keycloak <https://www.keycloak.org>`__ server which will be used as identity provider for the authentication. Then we will install JupyterHub locally and configure it to launch notebooks on the Slurm cluster.
