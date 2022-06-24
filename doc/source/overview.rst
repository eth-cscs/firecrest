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
In this way, every request made to the FirecREST API arrives first at the gateway, which will proxy the request towards the requested microservice endpoint.
However, before the request is passed on to the microservice, the gateway will enforce that the request is correctly authenticated and authorized by requiring and validating the Access Token that must accompany each API request.
The current implementation of the gateway service is based on the Kong API gateway.
Kong is a widely used opensource microservice API gateway that implements functionalities such as a variety of authentication and authorization mechanisms, support for OIDC, IP filtering, access control lists, analytics, rate limiting, among many others that have allowed us to configure the gateway to our requirements.

Status microservice
-------------------

Checks systems and services availability.
The Status microservice provides information of infrastructure and services.

Compute microservice
--------------------

The  compute microservice implements the interface to the workload manager, thus allowing applications to submit, stop, and  query  the  status  of jobs by using non-blocking asynchronous API calls.
This service depends on: the `tasks microservice <#tasks-microservice>`__ that  provides  a  temporal resource that tracks the state of each call; and, the `delegation microservice <#delegation-microservice>`__ that issues a restricted SHH certificate that allows the execution of operations on behalf of  the  user.

Storage microservice
--------------------

This microservice enable users the upload and downloadof large files to/from CSCS, while also enabling the movement  of  data  within  the  different  filesystems  available  on the  system .
It does so by using non-blocking calls to high-performance storage services while immediately responding with a reference to a resource that tracks the state of the request.

Tasks microservice
------------------

The task microservice responds to the need of managing the state of request that are being resolved asynchronously.
One clear example for the need of this microservice can be observed in the asynchronous data transfer operations handled by the storage microservice, as otherwise some of those workflows would not be possible.
As such, FirecREST microservices during  an  asynchronous  request  can  rapidly create and respond with a new task resource.
The operational result of the request is then tracked as the originating microservice continuously updates the task as progress is being made.
Thus, task resources allow a client to perform other activities while a FirecREST asynchronous tasks  are completed.

Utilities microservice
----------------------

The utilities microservice provides **synchronous** execution of some basic linux commands.
As calls to the utilities microservice are blocking operations, these have a timeoutand are not recursive.

Delegation microservice
-----------------------

The delegation microservice is a FirecREST internal service that is not exposed to the user.
This service takes avalid JWT access token as input and creates a short-lived SSH certificate to be used to user authentication.


FirecREST IAM
=============

The  Identity  and  Access  Management  (IAM)  infrastructure at CSCS ensures that users and web applications have the  appropriate  permissions  to  access  resources  at  CSCS by  using  a  secure  protocol.
From  the  whole  of  the  IAM infrastructure  at  CSCS  we  will  only  discuss  Keycloak,  the Identity  and  Access  Management  solution  deployed  at  thecenter.
Keycloak  allows  to  secure  application  and  services by  providing  a  mechanism  for  the  authentication  and  authorization  of  CSCS  users,  CSCS  services,  and  third  party applications.

Among  the  many  features  of  Keycloak  we highlight the following:

- single sign-on solution
- integration with Kerberos authentication service
- fine-grained authorization controls for services
- client registration and authorization
- support of OpenID Connect (OIDC) protocol

The  integration  of  FirecREST  with  Keycloak  has  been achieved  through  the  use  of  the  OIDC  protocol.
OIDCis  an  authentication  protocol  that  extends  the  OAuth  2.0 specification.
OAuth  2.0  is  an  industry-standard  protocol for  token-based  authorization  that  is  commonly  used  as  a mechanism  for  users  to  grant  access  permission  to  web application  in  order  to  access  user-owned  resources  and services.
The  extensions  provided  by  OIDC  to  the  OAuth2.0  protocol  add  a  user  authentication  layer,  providing  a mechanism that enables single sign-on to users.
FirecREST leverages on Keycloak and OIDC for authentication and authorization of web applications, enabling the following capabilities:

- enforce that all requests are authenticated
- applications never manipulate user credentials
- only allow requests from registered applications
- user-managed access permissions per application
- stateless security model by use of tokens
- short lifespan for sensitive access tokens
- extended client sessions allowed through refresh tokens

In a nutshell, FirecREST OIDC-based IAM enables theuser to login to a registered web application using their CSCS credentials and grant a web application with access to user-owned resource at the Center.
Moreover, it does so without the user ever sharing their credentials with the web application.
