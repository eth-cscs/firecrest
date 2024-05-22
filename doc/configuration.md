# FirecREST configuration

FirecREST microservices read their configuration from environment variables


## Type of variables

- Booleans: the following values can be taken as boolean

  - For True: `'True'`, `'yes'`, `'1'`, `1` 
  - For False: `'False'`, `'no'`, `'0'`, `0`

- Numeric

- Strings: single or double quotes can be used

## FirecREST hosts

These are the hosts where FirecREST is going to be installed.

The most complete way of installing is to setup 3 hosts:

- `Gateway`: for installing the Kong Gateway instance and interface public networks

- `Backend`: for installing FirecREST containers/microservices (`compute`, `status`, `storage`, `tasks` - `taskspersistence` (redis), and `utilities`) and only been accessed via the Gateway

- `Certificator`: for installing the Certificate Authority container/microservice (`certificator`), given that is the service that creates SSH keys on behalf of the users, it might be a good practice to isolate it and only be accessed via the `Backend` host.

**Note**: the setup can be done in only one virtual/bare metal host.

## Variables configured globally

### Need to set the value to adapt to your deployment

| **Name** | **Needs to be configured?** | **Default value** | **Definition** | **Hosts where it's used** | **Change from this version** | 
| ------ | -----------  | ------ | ----- | ---- | ----------------- |
|`F7T_AUTH_PUBLIC_KEYS`      | **YES** | `''`  | Value of [OIDC/OAuth2 Server Public Client Keys](https://datatracker.ietf.org/doc/html/rfc6749#section-2.1). This is the public key used for the Identity Provider (IdP) to sign the [JWT Access Token](https://jwt.io/introduction). If there are more than one IdP, list the public keys in a semicolon separated list | `Backend`, `Certificator`, `Gateway` | |
|`F7T_AUTH_ALGORITHMS`            | **YES** | `'RS256'`  | Value of [cryptographic algorithm used to sign JWT](https://datatracker.ietf.org/doc/html/rfc7518#section-3). Values are found in the `alg` part of the header of the JWT (`"alg": "RS256"`, `"alg": "HS256"`, etc). If there are more than one IdP, list algorithms in a semicolon separated list following the order of the keys in `F7T_AUTH_PUBLIC_KEYS` | `Backend`, `Certificator`, `Gateway` | |
|`F7T_SYSTEMS_PUBLIC_NAME`            | **YES** | `''`  | Public name(s) of the systems/HPC clusters interfaced by FirecREST. This name is a "familiar" name for users/clients. If more than one system is interfaced by FirecREST, then set this value with a semicolon separated list of names | `Backend` | Replaces `F7T_SYSTEMS_PUBLIC` |
|`F7T_SYSTEMS_INTERNAL_ADDR`  | **YES** | `''`  | Internal socket address  (DNS or IP, and SSH port), in the form `<DNS_or_IP>:<SSH_port>`, of the host used for SSH connection and command execution in relative order of `F7T_SYSTEMS_PUBLIC_NAME` (example: `192.168.220.12:22`, `cluster01.svc.com:22;cluster02.svc.com:22`). This is usually a **"login node"** of the HPC system| `Backend` | New on this version |
|`F7T_STATUS_SERVICES`           | **YES** | `''`  | Semicolon separated list of FirecREST services to report status (example: `compute;storage;utilities`) |  `Backend` |
|`F7T_OBJECT_STORAGE`            | **YES** | `'s3v4'`  | Object Storage Technology name used as staging area. Supported values: [`'swift'`](https://docs.openstack.org/swift/latest/), [`'s3v2'`](https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html), [`'s3v4'`](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html) | `Backend` |
|`F7T_FILESYSTEMS` | **YES** | `{}` | Dictionary object with information on filesystems present in each `F7T_SYSTEMS_PUBLIC_NAME` machine. You can set per filesystem a public `name`, the absolute root `path`, and a brief `description`. <br>Example:<br><pre><code>F7T_FILESYSTEMS="{'cluster01': [{'name':'PROJECT','path':'/project','description':'Project Filesystem'},</code><br><code>          {'name':'STORE', 'path':'/store', 'description':'Long term filesystem'},</code><br><code>    {'name':'SCRATCH', 'path':'/scratch', 'description':'Fast Lustre filesystem'} ],</code><br><code>'cluster02': [         {'name':'PROJECT','path':'/project','description':'Project Filesystem'},</code><br><code>          {'name':'STORE', 'path':'/store', 'description':'Long term filesystem'},</code><br><code>  {'name':'HOME', 'path':'/home', 'description':'Home filesystem'}] }"</code></pre> | `Backend`|

### Secrets

**IMPORTANT**: the values of the following variables are sensitive, it is important that you secure them and don't expose them in a public repository (GitLab, GitHub, etc)

| **Name** | **Needs to be configured?** | **Default value** | **Definition** | **Hosts where it's used** |  **Change from this version** | 
| -------- | -----------  | ----------------- | --------- | ---- | ------- |
|`F7T_PERSIST_PWD`| **YES** |  `''` | Password of the redis database used in `taskpersistence` container |  `Backend` | |



### Can be left as default

| **Name** | **Needs to be configured?** | **Default value** | **Definition** | **Hosts where it is used** |  **Change from this version** | 
| -------- | -----------  | ----------------- | --------- | ---- | ------ |
|`F7T_CERTIFICATOR_HOST`| NO | `'127.0.0.1'` | Hostname, IP or DNS of machine where the container for the `certificator` microservice is executed| `Backend`, `Certificator` | Replaces `F7T_CERTIFICATOR_URL` |
|`F7T_COMPUTE_HOST`     | NO | `'127.0.0.1'` | Hostname, IP or DNS of the container for the `compute` microservice| `Backend`, `Gateway` | Replaces `F7T_COMPUTE_URL` |
|`F7T_RESERVATION_HOST` | NO | `'127.0.0.1'` | Hostname, IP or DNS of the container for the `reservation` microservice| `Backend`, `Gateway` (deprecated) |  Replaces `F7T_RESERVATION_URL` | 
|`F7T_STATUS_HOST`      | NO | `'127.0.0.1'` | Hostname, IP or DNS of the container for the `status` microservice| `Backend`, `Gateway` |  Replaces `F7T_STATUS_URL` | 
|`F7T_STORAGE_HOST`     | NO | `'127.0.0.1'` | Hostname, IP or DNS of the container for the `storage` microservice| `Backend`, `Gateway` |  Replaces `F7T_STORAGE_URL` | 
|`F7T_TASKS_HOST`       | NO | `'127.0.0.1'` | Hostname, IP or DNS of the container for the `tasks` microservice| `Backend`, `Gateway` |   Replaces `F7T_TASKS_URL` | 
|`F7T_UTILITIES_HOST`   | NO | `'127.0.0.1'` | Hostname, IP or DNS of the container for the `utilities` microservice| `Backend`, `Gateway` |    Replaces `F7T_UTILITIES_URL` | 
|`F7T_CERTIFICATOR_PORT`| NO | `'5000'`      | TCP Port where the `certificator` microservice is exposed| `Certificator`, `Gateway` |
|`F7T_COMPUTE_PORT`     | NO | `'5006'`      | TCP Port where the `compute` microservice is exposed| `Backend`, `Gateway` |
|`F7T_RESERVATIONS_PORT`| NO | `'5005'`      | TCP Port where the `reservations` microservice is exposed| `Backend`, `Gateway`  (deprecated) |
|`F7T_STATUS_PORT`      | NO | `'5001'`      | TCP Port where the `status` microservice is exposed| `Backend`, `Gateway` |
|`F7T_STORAGE_PORT`     | NO | `'5002'`      | TCP Port where the `storage` microservice is exposed| `Backend`, `Gateway` |
|`F7T_TASKS_PORT`       | NO | `'5003'`      | TCP Port where the `tasks` microservice is exposed| `Backend`, `Gateway` |
|`F7T_UTILITIES_PORT`   | NO | `'5004'`      | TCP Port where the `utilities` microservice is exposed| `Backend`, `Gateway` |
|`F7T_SSL_ENABLED`          | NO | `True`        | Set to `True` if it's desired to expose internal microservices with HTTPS (recommended) | `Backend`, `Certificator` | Replaces `F7T_USE_SSL` |
|`F7T_SSL_CRT`          | Only if `F7T_SSL_ENABLED=True`   | `''`        | Path to the SSL Certificate Key for exposing the container with HTTPS protocol (recommended). | `Backend`, `Certificator` |
|`F7T_SSL_KEY`          | Only if `F7T_SSL_ENABLED=True`   | `''`        | Path to the SSL Public Key for exposing the container with HTTPS protocol (recommended). Only used if `F7T_SSL_ENABLED=True`  | `Backend`, `Certificator` |
|`F7T_DEBUG_MODE`       | NO  | `False`     | Set to `True` to log debug type information | `Backend` |
|`F7T_LOG_PATH`         | NO  | `/var/log`  | Directory path in container's filesystem where the logs will be stored | `Backend` |
|`F7T_LOG_TYPE`         | NO  | `file`      | Type of logs. Valid values are `file` and `stdout` | `Backend` |
|`F7T_GUNICORN_LOG`     | NO  | `--error-logfile ${F7T_LOG_PATH}/<service>.gunicorn.log` | Logs configuration for Gunicorn Web Server (the server used to expose microservice's containers), Set to empty for stdout output. For more information please refer to [Gunicorn Settings](https://docs.gunicorn.org/en/stable/settings.html) | `Backend`|
|`F7T_GUNICORN_SSL`     | NO  | `--ciphers TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_128_GCM_SHA256,DHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-AES128-GCM-SHA256 --ssl-version TLSv1_2 --keyfile $F7T_SSL_KEY --certfile $F7T_SSL_CRT` |SSL configuration for Gunicorn Web Server (the server used to expose microservice's containers). For more information please refer to [Gunicorn Settings](https://docs.gunicorn.org/en/stable/settings.html) | `Backend`|
|`F7T_GUNICORN_WORKER`  | NO  | `--workers=1 --threads=1` | Worker configuration for Gunicorn Web Server (the server used to expose microservice's containers). For more information please refer to [Gunicorn Settings](https://docs.gunicorn.org/en/stable/settings.html) | `Backend`|
|`F7T_JAEGER_AGENT`     | NO  | `''`  | Set this value to the Hostname (IP or DNS) of the [Jaeger](https://www.jaegertracing.io/docs/1.54/getting-started/) tracing instance. Port is fixed at `6831/UDP`, no need to set it up (example: `F7T_JAEGER_AGENT=192.168.220.50`) | `Backend`, `Certificator`|
|`F7T_OPA_ENABLED`          | NO  | `False` | Set this value to `True` if the [OPA](https://www.openpolicyagent.org/docs/latest/) instance is needed for whitelisting which users can execute commands through FirecREST |  `Backend`, `Certificator`|
|`F7T_OPA_URL`          | NO  | `http://localhost:8181` | Set this variable with the form `<schema>://host:port` where the [OPA](https://www.openpolicyagent.org/docs/latest/) instance is running. Only used if `F7T_OPA_ENABLED=True` |  `Backend`, `Certificator`|
|`F7T_OPA_POLICY_PATH`  | NO  | `v1/data/f7t/authz`     | Set the [OPA](https://www.openpolicyagent.org/docs/latest/) policy path value. Only used if `F7T_OPA_ENABLED=True`  |  `Backend`, `Certificator`|
|`F7T_AUTH_HEADER_NAME`  | NO | `'Authorization'` | Name of the header on the request for FirecREST where the [Access Token](https://datatracker.ietf.org/doc/html/rfc6749#section-1.4) is set | `Backend`, `Certificator` |
|`F7T_AUTH_ROLE`               | NO | `''` | For `client_credentials` [OIDC/OAuth2 grant type](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4), is the name of the role in `["realm_access"]["roles"]` list where the system username is set in the JWT | `Backend`, `Certificator` |
|`F7T_AUTH_REQUIRED_SCOPE`     | NO | `''` | Name of the [access token scope](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3) used to allow client application to access FirecREST. This depends on the configuration of the IdP. If there are more scopes set by the IdP for the application, use a semicolon separated list of values    | `Backend`, `Certificator` |
|`F7T_AUTH_TOKEN_AUD`          | NO | `''` | Name of the [access token audience](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3) used to allow client application to access FirecREST. This depends on the configuration of the IdP | `Backend`, `Certificator` |
|`F7T_UTILITIES_MAX_FILE_SIZE` | NO | `5` | Value in **megabytes** of the maximum size of file that can be uploaded/downloaded using `/utilities` | `Backend` |
|`F7T_UTILITIES_TIMEOUT`       | NO | `5` | Value in **seconds** for timing out a login node command using `/utilities` | `Backend` |
|`F7T_PERSIST_HOST`            | NO | `'127.0.0.1'` | Hostname or IP of the redis database used in `taskpersistence` container |  `Backend` | Replaces `F7T_PERSISTENCE_IP` |
|`F7T_PERSIST_PORT`            | NO | `'6379'` | Port number of the redis database used in `taskpersistence` container |  `Backend` |
|`F7T_SPANK_PLUGIN_ENABLED`        | NO | `False`   | Set to `True` if the system scheduler uses a [spank](https://slurm.schedmd.com/spank.html) when submitting jobs. If there is more than one system configured, there should be a semicolon separated list in relative order to `F7T_SYSTEMS_PUBLIC_NAME` values |  `Backend`| Replaces `F7T_USE_SPANK_PLUGIN` |
|`F7T_SPANK_PLUGIN_OPTION` | only if `F7T_SPANK_PLUGIN_ENABLED=True` | `--nohome`| Name of the option to use in the workload manager command. If there is more than one system configured, there should be a semicolon separated list in relative order to `F7T_SYSTEMS_PUBLIC_NAME` values |  `Backend`|
|`F7T_COMPUTE_SCHEDULER`  | NO | `'Slurm'`| Set to the name of the of the Workload Manager scheduler adapter class. By default it can be found in `/src/common/schedulers` | `Backend`|
|`F7T_SSH_CERTIFICATE_WRAPPER_ENABLED`  | NO | `False`| If set to `True` it enables FirecREST to send an SSH Certificate as command for execution. Requires a serverside [SSH ForceCommand](https://shaner.life/the-little-known-ssh-forcecommand/) wrapper | `Backend`| Replaces `F7T_SSH_CERTIFICATE_WRAPPER` |
|`F7T_CA_KEY_PATH`| NO | `'/ca-key'` | Set the absolute path in the `certificator` container where the Private Key for creating SSH certificates is stored | `Certificator`| 
|`F7T_PRIV_USER_KEY_PATH`| NO | `'/user-key'` | Set the absolute path in the containers on `Backend` where the user Public Key is stored in order to create SSH certificates |  `Backend` |
|`F7T_PUB_USER_KEY_PATH`| NO | `'/user-key.pub'` | Set the absolute path in the containers on `Backend` where the user's Private Key is stored in order to create SSH certificates | `Certificator` |
|`F7T_SYSTEMS_INTERNAL_STATUS_ADDR`   | NO | the value on `F7T_SYSTEMS_INTERNAL_ADDR` | Internal socket address  (DNS or IP, and SSH port) of the host used for **testing system availability via SSH**  in the form `<DNS_or_IP>:<SSH_port>` in relative order of `F7T_SYSTEMS_PUBLIC_NAME` (example: `192.168.220.12:22`, `cluster01.svc.com:22;cluster02.svc.com:22`). **Note**: Set this variable only if you use a dedicated server for  `status` microservice | `Backend` | Replaces `F7T_STATUS_SYSTEMS` |
|`F7T_SYSTEMS_INTERNAL_COMPUTE_ADDR`  | NO |the value on `F7T_SYSTEMS_INTERNAL_ADDR`   | Internal socket address (DNS or IP, and SSH port) of the host used for **job submissions on the workload manager** (SLURM, PBS, LSF, etc) in the form `<DNS_or_IP>:<SSH_port>` in relative order of `F7T_SYSTEMS_PUBLIC_NAME` (example: `192.168.220.12:22`, `cluster01.svc.com:22;cluster02.svc.com:22`). **Note**: Set this variable only if you use a dedicated server for `compute` microservice | `Backend` |
|`F7T_SYSTEMS_INTERNAL_STORAGE_ADDR`  | NO | the value on `F7T_SYSTEMS_INTERNAL_ADDR`   | Internal socket address (DNS or IP, and SSH port) of the host used for **moving data between Filesystems and Object Storage** in the form `<DNS_or_IP>:<SSH_port>` in relative order of `F7T_SYSTEMS_PUBLIC_NAME` (example: `192.168.220.12:22`, `cluster01.svc.com:22;cluster02.svc.com:22`). **Note**: Set this variable only if you use a dedicated server for `storage` microservice| `Backend` |
|`F7T_SYSTEMS_INTERNAL_UTILITIES_ADDR`| NO |the value on `F7T_SYSTEMS_INTERNAL_ADDR`   | Internal socket address (DNS or IP, and SSH port) of the host used for **small filesystem operations** in the form `<DNS_or_IP>:<SSH_port>` in relative order of `F7T_SYSTEMS_PUBLIC_NAME` (example: `192.168.220.12:22`, `cluster01.svc.com:22;cluster02.svc.com:22`). **Note**: Set this variable only if you use a dedicated server for `utilities` microservice| `Backend` |
|`F7T_STORAGE_TEMPURL_EXP_TIME` | NO | `'604800'` | Values in **seconds** of the expiration time set for URLs generated from the Object Storage in `storage` microservice | `Backend` |
|`F7T_STORAGE_MAX_FILE_SIZE`    | NO | `'5120'`   | Values in **megabytes** of the maximum allowed size for a single object transfer using the Object Storage in `storage` microservice | `Backend` |
|`F7T_COMPUTE_TASK_EXP_TIME`     | NO | `'86400'`   | Values in **seconds** of the expiration time set on `redis` for tasks generated in `compute` microservice | `Backend` |
|`F7T_STORAGE_TASK_EXP_TIME`     | NO | the value on `F7T_STORAGE_TEMPURL_EXP_TIME`   | Values in **seconds** of the expiration time set on `redis` for tasks generated in `storage` microservice (only `xfer-external`) | `Backend` |


## Variables only needed in STORAGE container

**Important** FirecREST provides support for 2 Object Storage technologies: OpenStack Swift and AWS S3. Depending on your infrastructure or cloud needs, you can select in the variable `F7T_OBJECT_STORAGE` any of these options:

- `'swift'`: for OpenStack Swift 
- `'s3v2'`: for AWS S3 with v2 signature
- `'s3v4'`: for AWS S3 with v4 signature (**by default and recommended**)

### Need to set the value to adapt to your deployment

| **Name** | **Needs to be configured?** | **Default value** | **Definition** | **Hosts where it's used** |   **Change from this version** | 
| -------- | -----------  | ----------------- | --------- | ---- | -- |
|`F7T_OS_AUTH_URL`               | only if `F7T_OBJECT_STORAGE='swift'` | `''` |OpenStack Keystone identity service endpoint for authentication for OIDC or SAML |  `Backend` |
|`F7T_OS_IDENTITY_PROVIDER`      | only if `F7T_OBJECT_STORAGE='swift'` | `''` | OpenStack Keystone Server Authentication Identity Provider Name for OIDC or SAML |  `Backend` |
|`F7T_OS_IDENTITY_PROVIDER_URL`  | only if `F7T_OBJECT_STORAGE='swift'` | `''` | OpenStack Keystone Server Authentication Identity Provider URL for SAML (example: `<idp_url>/auth/realms/<realm>/protocol/saml/`)|  `Backend` |
|`F7T_OS_KEYSTONE_AUTH`          | only if `F7T_OBJECT_STORAGE='swift'` | `''` | OpenStack Keystone Authentication Method. Supported values are `'oidc` and `'saml'` |  `Backend` |
|`F7T_OS_PROTOCOL`               | only if `F7T_OBJECT_STORAGE='swift'` | `'openid'` | OpenStack Keystone Protocol for federated plugin for OIDC or SAML|  `Backend` |
|`F7T_OS_PROJECT_ID`             | only if `F7T_OBJECT_STORAGE='swift'` | `''` | OpenStack Project ID of the Object Storage Service Account for FirecREST|  `Backend` | Duplicates `F7T_SWIFT_ACCOUNT` |
|`F7T_OS_CLIENT_ID`              | only if `F7T_OBJECT_STORAGE='swift'` | `''` | OIDC Client ID for token exchange between OIDC IdP and OpenStack Keystone |  `Backend` |
|`F7T_OS_DISCOVERY_ENDPOINT`     | only if `F7T_OBJECT_STORAGE='swift'` | `''` | Discovery endpoint for OIDC IdP (example: `<idp_url>/auth/realms/<realm>/protocol/.well-known/openid-configuration`) |  `Backend` |
|`F7T_SWIFT_PUBLIC_URL`          | only if `F7T_OBJECT_STORAGE='swift'` | `''` | Public URL of the Object Storage server|  `Backend` |
|`F7T_SWIFT_PRIVATE_URL`         | only if `F7T_OBJECT_STORAGE='swift'` | `'<F7T_SWIFT_PUBLIC_URL>'` | URL for internal connections in Data Center to the Object Storage server. Set only if it's different to `F7T_SWIFT_PUBLIC_URL`|  `Backend` |
|`F7T_SWIFT_API_VERSION`         | only if `F7T_OBJECT_STORAGE='swift'` | `'v1'` | OpenStack Swift API version|  `Backend` |
|`F7T_S3_PUBLIC_URL`             | only if `F7T_OBJECT_STORAGE='s3v2' or 's3v4'` | `''` | Public URL of the Object Storage server|  `Backend` |
|`F7T_S3_PRIVATE_URL`            | only if `F7T_OBJECT_STORAGE='s3v2' or 's3v4'` | `'<F7T_S3_PUBLIC_URL>'` | URL for internal connections in Data Center to the Object Storage server. Set only if it's different to `F7T_S3_PUBLIC_URL` |  `Backend` |
|`F7T_XFER_PARTITION`            | **YES** | `''` | Name, in relative order to `F7T_STORAGE_JOBS_MACHINE` of the workload manager **partition** that `storage` microservice use to moves data between filesystems. | `Backend` | 



### Secrets

**IMPORTANT**: the values of the following variables are sensitive, it is important that you secure them and don't expose them in a public repository (GitLab, GitHub, etc)

| **Name** | **Needs to be configured?** | **Default value** | **Definition** | **Hosts where it's used** |   **Change from this version** | 
| -------- | -----------  | ----------------- | --------- | ---- | ------- |
|`F7T_CERT_CIPHER_KEY`  | **YES** | `''`| value of the cipher key used to encrypt SSH certificates for large data transfer. FirecREST uses Fernet library to create these keys. Use the following code to create a new key before storing it in your secret management service: <br><pre><code>$ python3 </code><br><code>>>> from cryptography.fernet import Fernet</code><br><code>>>> Fernet.generate_key() </code><br><code>b'ADa7v8lnih7zB0JrhsZfqVEQlRujrClQXQRlRkNKS2Y='</code></pre> | `Backend` |
|`F7T_OS_CLIENT_SECRET`         | only if `F7T_OBJECT_STORAGE='swift'` | `''` | OIDC Client Secret for token exchange between OIDC IdP and Keystone |  `Backend` |
|`F7T_SWIFT_USER`               | only if `F7T_OBJECT_STORAGE='swift'` | `''` | UID of the Service Account user of the Object Storage |  `Backend` |
|`F7T_SWIFT_PASS`               | only if `F7T_OBJECT_STORAGE='swift'` | `''` | Password of the Service Account user of the Object Storage |  `Backend` |
|`F7T_SWIFT_SECRET_KEY`         | only if `F7T_OBJECT_STORAGE='swift'` | `''` | Secret key configured in [OpenStack Swift](https://docs.openstack.org/swift/latest/api/temporary_url_middleware.html#secret-keys) service to encrypt self-signed temporary URLs |  `Backend` | Replaces `F7T_SECRET_KEY` |
|`F7T_S3_ACCESS_KEY`            | only if `F7T_OBJECT_STORAGE='s3v2' or 's3v4'` | `''`| AWS S3 Access Key of the Service Account user of the Object Storage | `Backend` |
|`F7T_S3_SECRET_KEY`            | only if `F7T_OBJECT_STORAGE='s3v2' or 's3v4'` | `''`| AWS S3 Access Key of the Service Account user of the Object Storage | `Backend` |

### Can be left as default

| **Name** | **Needs to be configured?** | **Default value** | **Definition** | **Hosts where it's used** |
| -------- | -----------  | ----------------- | --------- | ---- |
|`F7T_STORAGE_POLLING_INTERVAL`| NO | `60` | Value in **seconds** of the period for polling if objects uploaded using `storage` microservice are completelly saved in the Object Storage |   `Backend` |
|`F7T_STORAGE_JOBS_MACHINE`    | NO | the value on `F7T_SYSTEMS_PUBLIC_NAME` | Name, in relative order to `F7T_SYSTEM_PUBLIC` of the **system** that `storage` microservice uses to move data between filesystems. | `Backend` | 
|`F7T_STORAGE_SCHEDULER`       | NO | the value on `F7T_COMPUTE_SCHEDULER` | Set to the name of the of the Workload Manager scheduler adapter class used by `storage` on  on `F7T_STORAGE_JOBS_MACHINE` to create jobs for Data Mover. By default it can be found in `/src/common/schedulers` | `Backend` | 
|`F7T_XFER_CONSTRAINT`         | NO | `''` | Set to the name of the constraint used by the Workload Manager on `F7T_STORAGE_JOBS_MACHINE` to create jobs for Data Mover | `Backend` | 
|`F7T_USE_SCHED_PROJECT`       | NO | `False` | Set `True` if the Workload Manager on `F7T_STORAGE_JOBS_MACHINE` needs to set the **account** parameter to create jobs for Data Mover | `Backend` | 
|`F7T_S3_REGION`                 | only if `F7T_OBJECT_STORAGE='s3v2' or 's3v4'` | `'us-east-1'` | Value of the region of AWS S3 service (check your AWS S3 instance configuration) |  `Backend` |
|`F7T_S3_TENANT`                 | only if `F7T_OBJECT_STORAGE='s3v2' or 's3v4'` | `None` | Value of the tenant of AWS S3 service (check your AWS S3 instance configuration) |  `Backend` |

## Variables only needed in COMPUTE container

### Need to set the value to adapt to your deployment

| **Name** | **Needs to be configured?** | **Default value** | **Definition** | **Hosts where it's used** |
| -------- | -----------  | ----------------- | --------- | ---- |
| `F7T_COMPUTE_BASE_FS` | **YES** | `/home` | Base directory in which the workload manager batch file is stored when using the `compute` microservice. The final destination would be `<F7T_COMPUTE_BASE_FS>/<uid>/firecrest` If there is more than one system configured, there should be a semicolon separated list in relative order to `F7T_SYSTEMS_PUBLIC_NAME` values  |   `Backend` |


### Can be left as default

| **Name** | **Needs to be configured?** | **Default value** | **Definition** | **Hosts where it's used** |
| -------- | -----------  | ----------------- | --------- | ---- |
| `F7T_TAIL_BYTES` | NO | `1000` | Amount of last bytes shown for the output of job in the workload manager | `Backend`|

 
 ## Variables only needed in RESERVATIONS container

 **IMPORTANT** to be deprecated soon

### Need to set the value to adapt to your deployment

| **Name** | **Needs to be configured?** | **Default value** | **Definition** | **Hosts where it's used** |
| -------- | -----------  | ----------------- | --------- | ---- |

### Can be left as default

| **Name** | **Needs to be configured?** | **Default value** | **Definition** | **Hosts where it's used** |
| -------- | -----------  | ----------------- | --------- | ---- |
| `F7T_RESERVATIONS_TIMEOUT` | NO | `30` | Value in **seconds** for timing out a login node command using `/reservations` | `Backend`|
| `F7T_RESERVATION_CMD`      | NO | `rsvmgmt` | Set to the command that will execute commands in the system | `Backend` | 