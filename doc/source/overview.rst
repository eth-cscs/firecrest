========
Overview
========

FirecREST in a nutshell
=======================

FirecREST is a web-enabled application programming interface (API)  to  High-Performance  Computing  (HPC)  resources  under development at CSCS.

Scientific platform developers can integrate the Firecrest API into their  web-enabled  portals  and  applications,  allowing  them  to securely  access  authenticated  and  authorized  CSCS  services such  as  job  submission,  data  mover  and  transfer  on  HPC systems.

FirecREST architecture
======================

FirecREST is comprised from a number of different microservices.

Gateway
-------
Not a microservice “per-se”, but entrypoint for request by users. Also provides load balancing, IP redirection and filtering, and authentication plugins.

Status
------

Checks systems and services availability.

Compute
-------

Allows job submission and accounting.

Storage
-------
Large data transfer and large data movements.

Tasks
-----
Saves asynchronous (Storage and Compute) tasks and serves as query for tasks status.

Utilities
---------

Entrypoint for filesystem common operations such as directories listing, small file transfers, object stats, etc



FirecREST IAM
=============

