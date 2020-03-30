========
Overview
========

FirecREST in a nutshell
=======================

FirecREST is a web-enabled application programming interface (API) to High-Performance Computing (HPC) resources under development at CSCS.

Scientific platform developers can integrate the Firecrest API into their  web-enabled  portals  and  applications,  allowing  them  to securely  access  authenticated  and  authorized  CSCS  services such  as  job  submission,  data  mover  and  transfer  on  HPC systems.

FirecREST architecture
======================

The core components and microservices that are part of FirecREST are the following:

Gateway
-------

The API gateway provides an interface to publish, maintain, monitor, and secure all the FirecREST API endpoints.
The gateway is hosted on a machine within CSCS that is facing the internet.
All interactions with the FirecREST API are first passed and validated before being redirected to any other FirecREST microservice.
In  this  way,  every  request  made  to  the  FirecREST  API arrives  first  at  the  gateway,  which  will  proxy  the  request towards the requested microservice endpoint.
However, before the request is passed on to the microservice, the gatewaywill enforce that the request are correctly authenticated and authorized  by  requiring  and  validating  the  Access  Token that  must  accompany  each  API  request.
The  current  implementation  of  the  gateway  service  is based on the Kong API gateway.
Kong is a widely used opensource microservice API gateway that implements functionalities such as a variety of authentication and authorization mechanisms,  support  for  OIDC,  IP  filtering,  access  control lists,  analytics, rate limiting, among many others that have allowed us to configure the gateway to our requirements.

Status microservice
-------------------

Checks systems and services availability.
The Status microservice provides information of infrastructure and services.

Compute microservice
--------------------

The  compute microservice implements the interface to the workload manager, thus allowing applications to submit, stop, and  query  the  status  of jobs by using non-blocking asynchronous API calls.
This service depends on: the `tasks microservice <#tasks-microservice>`_ that  provides  a  temporal resource that tracks the state of each call; and, the delegation microservice (see section III-F) that issues a restricted SHH certificate that allows the execution of operations on behalf of  the  user.

Storage microservice
--------------------
Large data transfer and large data movements.

Tasks microservice
------------------
Saves asynchronous (Storage and Compute) tasks and serves as query for tasks status.

Utilities microservice
----------------------

Entrypoint for filesystem common operations such as directories listing, small file transfers, object stats, etc



FirecREST IAM
=============

