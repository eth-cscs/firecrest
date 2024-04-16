# Setup FirecREST in a new site

This document describes how FirecREST and 3rd party components integrate, and how to set them up for a cluster. Additional configuration information can be found at `docs/configuration.md`

### Table of contents
- [External components](#external-components)
    - [IAM infrastructure](#iam-infrastructure)
    - [Gateway](#gateway)
    - [Object Storage](#object-storage)
    - [Redis](#redis)
    - [Tracing](#tracing)
    - [Cluster integration](#cluster-integration)
    - [Workload manager](#workload-manager)
- [Installation procedure](#installation-procedure)
- [FirecREST microservices setup](#f7t-microservices-setup)
    - [Common setup](#common-setup)
    - [Certificator](#certificator)
    - [Compute](#compute)
    - [Reservations](#reservations)
    - [Storage](#storage)
    - [Tasks](#tasks)
    - [Utilities](#utilities)
    - [Logging](#logging)


### External components

The FirecREST demo uses 3rd party applications to show for full functionality:
  - Keycloak is used as authentication provider
  - Kong is an API gateway
  - Redis is used by the Task microservice for data persistence
  - Minio is an S3-compatible object store. Storage microservice uses it for asynchronous file transfers between the cluster and the user
  - Jaeger is an optional component for tracing
  - OPA (Open Policy Agent) is an optional service to provide authorization

In a custom deployment, they can be changed or removed.

These applications and FirecREST microservices can be deployed in the same machine or in different ones. Also, one installation can provide access to several HPC systems.


### IAM infrastructure

FirecREST relies on an OIDC provider, like Keycloak, to authenticate the users and act on their behalf. It does not store any user credential or has any user database.

The OIDC provider does not need to communicate directly with any of the services of FirecREST and can use any OIDC authentication flow. It only needs to provide the user with a valid JSON Web Token (JWT) in one of the following forms:
- as a client:
```json
{
  "clientId": <client_id>,
  "realm_access": {
    "roles": [
      <F7T_AUTH_ROLE>
    ]
  },
  "resources_access": {
    <client_id>: {
      "roles": [<username>]
    }
  }
  "scope": <F7T_AUTH_REQUIRED_SCOPE>,
  ...
}
```

- as a user:
```json
{
  "preferred_username": <username>,
  "scope": <F7T_AUTH_REQUIRED_SCOPE>,
  ...
}
```

This will have to match FirecREST's environment variables: `F7T_AUTH_ROLE` and `F7T_AUTH_REQUIRED_SCOPE`. For the first type of token, if the variable `F7T_AUTH_ROLE` is set, it defines the role to check and FirecREST will search the user's name in the shown field. Otherwise FirecREST will try to get the user's name from the `preferred_username` field.

If the variable `F7T_AUTH_REQUIRED_SCOPE` is set, FirecREST checks the field is present on the JWT and that it matches. If empty or undefined, no check is performed.

The environment variable `F7T_REALM_RSA_PUBLIC_KEY` holds the RSA public key from the OIDC provider.
It is used to validate JWT tokens included on requests (via 'Authorization' header). If empty, no verification is made on the token, which is only useful for debugging. Additionally, if not running in debug mode (`F7T_DEBUG_MODE`) microservices will log a warning. As some systems are tricky with variables containing multiple lines, define the variable using only one line without headers (`-----BEGIN PUBLIC KEY-----`, `-----END PUBLIC KEY-----`), they will be added by F7T.

For Keycloak, the signing public key and the endpoints can be retrieved from https://KEYCLOAK_URL/auth/realms/REALM_NAME/

Depending on the chosen authentication workflow, a user and/or a client are required. The demo Keycloak can be used for testing, information on how to access is at `deploy/demo/README.md`

It must be noted that FirecREST can also work without an OIDC provider. In some cases, for example when an application already handles authentication, it can also generate and sign tokens. As in the previous case, the signing public key and algorithm must be configured on FirecREST.

Optionally, an OPA service can be used for authorization.


### Gateway

The services of FirecREST are designed to be behind a central gateway, like Kong. This gateway is exposed to users and/or client applications to make requests, which are forwarded to the microservices. This allows to filter which endpoints and methods are publicly available, verify the JWT, add tracing information and rate limit requests.

For configuration, this service requires:
- OIDC realm URL and public key, to verify the JWT
- URL of F7T microservices Compute, Status, Storage, Tasks, Utilities
- optional: Jaeger endpoint (using Zipkin protocol) https://docs.konghq.com/hub/kong-inc/zipkin/

Note: this service must not expose Certificator microservice.

A sample configuration which uses Kong without a database is included on `deploy/demo/kong/kong.yml`


### Object Storage

FirecREST uses an external object store (OS) to transfer large quantities of data. When a user requests to upload or download a file, FirecREST creates a container in the OS and provides a direct URL that can be used without credentials.

For configuration, this service requires:
- for Minio: define `MINIO_ACCESS_KEY` and `MINIO_SECRET_KEY` which match variables `F7T_S3_ACCESS_KEY` and `F7T_S3_SECRET_KEY` to pass to Storage microservice.
- for Swift: configure a service account (preferred). Depending on the exposed interface (Swift of S3) and version, select the appropriate variables from `doc/configuration.md` to pass to Storage microservice.


### Redis

Redis is used by the Task microservice as a key-value store that can persist data on disk. It does not need to connect to any other service.

For configuration, this service requires:
- define password and port (standard is 6379). Then set `F7T_PERSIST_HOST`, `F7T_PERSIST_PORT`, `F7T_PERSIST_PWD` for the Task microservice


### Tracing

Jaeger is used to provide tracing between microservices and some performance metrics. If a trace ID is available, it is also embedded in the command executed on the HPC machine and it becomes possible to track a request from the gateway, through microservices, command execution and response.

For configuration, this service requires:
- for integration with Kong, set `COLLECTOR_ZIPKIN_HOST_PORT=9411`
- set `F7T_JAEGER_AGENT` with the IP of the service, FirecREST microservices use standard `6831/UDP` to send traces


### Cluster integration

FirecREST has a delegation microservice, named Certificator, that allows to perform actions on behalf of the user. It takes the username defined in the JWT and creates an SSH certificate to execute commands on behalf of the user.

FirecREST microservices connect via SSH to one or more machines to execute compute, storage and utilities related commands. These machines are defined as lists on `F7T_SYSTEMS_INTERNAL_ADDR`. To be able to authenticate, the SSH server must trust a SSH Certificate Authority (CA) key.

If different login nodes has been setup for executing different functionalities of FirecREST, those machines can be set using the variables `F7T_SYSTEMS_INTERNAL_STATUS_ADDR`
`F7T_SYSTEMS_INTERNAL_COMPUTE_ADDR`, `F7T_SYSTEMS_INTERNAL_STORAGE_ADDR` and `F7T_SYSTEMS_INTERNAL_UTILITIES_ADDR` respectively. 


### Workload manager
Currently, Slurm is the only one supported. Large internal data transfers are performed as a job in an specific partition.


## Installation procedure

In this setup, the microservices and 3rd party applications run inside containers, so they do not require additional software aside from a container engine. However, it is also possible to run them natively or in a mixed setup.

The machine(s) that executes commands from users (job submission, file copying, etc) can be part of the cluster (e.g. a login node) or not. In the later case, it has to be able to interact with the Slurm installation and the desired filesystems.

Everything can be configured in the same machine, depending on resources, load and security considerations. In the following setup, two machines are assumed: one where the containers with FirecREST and 3rd applications run and another one where the commands (Slurm, etc) are executed.

For an initial setup, the configuration of the demo environment can serve as a base that can be connected to your cluster. First, create the containers for the microservices:
```bash
# define absolute paths for simplicity
export F7T_GIT_DIR=/path/to/f7t/git/dir
export F7T_INSTALL=/path/to/your/install
cd $F7T_GIT_DIR
cd deploy/demo
# create container images
docker-compose build f7t-base certificator client compute reservations status storage tasks utilities
# check they were created
docker images
```

Than copy the configuration and directories to your new directory:
```bash
# create the install directory if necessary
mkdir -p $F7T_INSTALL
cd $F7T_INSTALL
# copy demo configuration as starting point
cp -a $F7T_GIT_DIR/deploy/demo/* .
```

Edit this new `$F7T_INSTALL/common/common.env` to point to your cluster or SSH server and optionally customize other options, for example:
```bash
F7T_SYSTEMS_PUBLIC_NAME='mycluster'
# define IP or hostname to execute commands, in the same order as the systems. Can be the same machine
F7T_SYSTEMS_INTERNAL_ADDR='IP:PORT'
F7T_SYSTEMS_INTERNAL_STATUS_ADDR='IP:PORT'
F7T_SYSTEMS_INTERNAL_COMPUTE_ADDR='IP:PORT'
F7T_SYSTEMS_INTERNAL_STORAGE_ADDR='IP:PORT'
F7T_SYSTEMS_INTERNAL_UTILITIES_ADDR='IP:PORT'
# system to send transfer jobs
F7T_STORAGE_JOBS_MACHINE='mycluster'
# Slurm partition where transfer jobs run
F7T_XFER_PARTITION='normal'
# disable OPA
F7T_OPA_ENABLED=False
```

As mentioned on the [IAM section](#iam-infrastructure), a user must exist on both the OIDC provider and the cluster. This demo setup has users `test1` and `test2` defined on Keycloak, so either create these users on your cluster, add the user(s) on Keycloak that match the one(s) on your machine, or connect to your own OIDC provider.

Then create an SSH Certificate Authority (CA) and SSH user keys:
```bash
ssh-keygen -t ed25519 -b 521 -P "" -f common/ca-key -C "CA Authority-f7t"
ssh-keygen -t ed25519 -b 256 -P "" -f common/user-key
# by default 'ca-key' and 'user-key' have correct permissions (400)
# change docker-compose.yml to use these files:
sed --in-place=.bak -e 's#../test-build/environment/keys/#./common/#'  docker-compose.yml
```

The CA private key (`common/ca-key`) has to be available only to the Certificator microservice and has to be handle securely as it allows to generate SSH certificates for any user. Also keep its permissions to 400 (only owner can read).

Edit `docker-compose.yml` and comment the `cluster` section as it not required. Then start FirecREST and 3rd party services:
```bash
# start the containers
docker-compose up -d
# check all services are up
docker ps
```

After this, the services should be running: the gateway is listening at port *8000* and Keycloak at *8080*.

Now it is necessary to configure the SSH server on the cluster or machine that executes the commands. Copy `common/ca-key.pub` to the server machine(s) server at `/etc/ssh/ca-key.pub`, make sure the owner is *root* and check others do not have write permissions. Then add configuration to trust the key on `/etc/ssh/sshd_config`:
```
# IP or block of the FirecREST microservices
Match Address 192.168.10.30
    TrustedUserCAKeys /etc/ssh/ca-key.pub
    # only accept this CA, and not regular priv/pub SSH keys
    PubkeyAcceptedKeyTypes ssh-rsa-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com
    PermitRootLogin  no
    DenyGroups root bin admin sys
    MaxAuthTries 1
    AllowTcpForwarding no
    # optional: filter and log every connection
    ForceCommand /etc/ssh/ssh_command_wrapper.sh
    PermitTTY no
    PermitTunnel no
```

In this example, the SSH server will be receiving connections from microservices Compute, Tasks, Storage and Utilities from a machine *192.168.10.30*.

The optional ForceCommand is a recommended additional safe protection. It executes an script which checks the command or application is allowed and logs the action. An example can be found in `deploy/test-build/cluster/ssh/ssh_command_wrapper.sh` This file should have permissions *555* or *755* as it will be executed by the users.

Finally, restart the SSH service to apply the changes and the setup is complete.


## FirecREST microservices setup

This section describes the microservices' configuration and their relations. Note that a microservice must be restarted to read the new values.

### Common setup

It is recommended to create a configuration file that can be shared by all microservices. This file should include systems and the machines were commands are executed, OIDC parameters, timeouts, etc. Secrets should be passed separately to the specific services, currently this applies to Storage (related to object storage) and Tasks (to access Redis). A sample file can be found at `deploy/demo/common/common.env`

Currently, some variables like `F7T_UTILITIES_TIMEOUT` are required in most microservices and not just Utilities.

Ir order to use SSH certificates, a standard SSH pair key is also required. These keys are not security sensitive because authentication depends on the certificate and not on these keys, but it must not be trusted in any SSH `authorized_keys` file or reused elsewhere. They can be generate with
```bash
ssh-keygen -t ed25519 -b 256 -P "" -f user-key
```

The private key (`user-key`) must only be readable by the owner (permissions mode `400`), which must be also the user running the microservice. This file is required by Compute, Reservation, Storage and Utilities, and must be in the same directory as the microservice code.

The public key (`user-key.pub`) is only required by Certificator and must be in the same directory as the microservice code.

The following variables are not required by every microservice, but for simplicity they can be put together in the same file:
- `F7T_CERTIFICATOR_HOST`, `F7T_COMPUTE_HOST`, `F7T_RESERVATIONS_HOST`, `F7T_STORAGE_HOST`, `F7T_TASKS_HOST`, `F7T_UTILITIES_HOST`: internal HostName, DNS, IP (not exposed to users) used by microservices to communicate between them.
- `F7T_REALM_RSA_PUBLIC_KEY`, if defined also requires: `F7T_REALM_RSA_TYPE`
- `F7T_SYSTEMS_PUBLIC_NAME`: list of systems names, as seen by users.

There are additional options at `doc/configuration.md`

#### Logging

Each microservices generates two log files: one for Gunicorn and one for the microservice. Location of the files can be specified with `F7T_LOG_PATH`, default is `/var/log`

If `F7T_DEBUG_MODE` is `True` (default is `False`), then extra messages are added. This should not be active on production systems as it logs tokens and sensitive information.


### Certificator

This service requires two files:
- SSH CA private key (`ca-key`) must be owned by the user running the microservice and must be only readable by the owner (permissions mode `400`)
- SSH user public key (`user-key.pub`) has to be readable by the service, but ownership is not important.

Both files must be in the same directory as the microservice code.

Network connections to this service should be limited to the services which depend on it: Compute, Reservation, Storage, Status and Utilities


### Compute

No extra configuration required, file `user-key` must be available as described above. There are additional options at `doc/configuration.md`


### Reservations

No extra configuration required, file `user-key` must be available as described above.


### Storage

This service connects to the object storage so credentials must be exclusive to this service. Depending on the type of OS, relevant variables are:
- S3: `F7T_S3_ACCESS_KEY`, `F7T_S3_SECRET_KEY`
- Swift: `F7T_SWIFT_USER`, `F7T_SWIFT_PASS`, `F7T_SECRET_KEY`

Also variable `F7T_CERT_CIPHER_KEY` must be exclusive, it is used internally to protect long term certificates (for file downloading from OS to cluster) on the Redis database.

File `user-key` must be available as described above.


### Tasks

The variable `F7T_PERSIST_PWD` contains the Redis password and should be exclusive to this service.


### Utilities

No extra configuration required, file 'user-key' must be available as described above. There are additional options at `doc/configuration.md`
