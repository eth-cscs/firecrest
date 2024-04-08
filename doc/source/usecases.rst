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
