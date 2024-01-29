# FirecREST configuration

FirecREST microservices read their configuration from environment variables. Most of them can be stored in a shared file (`common.env`) and others should be passed independently, such as secrets or specific parameters.


The environment variables can be grouped in:
1. Service internal properties
    1. Service discovery and network properties (port, SSL, URL)
    2. Service behavior (debug, timeout, max file size)
    3. Task persistence (Redis)
    4. Gunicorn configuration
2. Site/cluster integration
    1. IAM integration
        1. OIDC integration with Keycloak
        2. OPA
    2. Clusters and internal machines that provide services
        1. Slurm parameters, Spank, transfer partition
        2. Reservation tool parameters
    3. Object Storage (credential, account, properties)
    4. Gateway (Kong)
    5. Tracing (Jaeger)



## 1. Service internal properties
| **Name** | **Required** | **Default value** | **Notes** |
| -------- | -----------  | ----------------- | --------- |
|`F7T_CERTIFICATOR_PORT`, `F7T_COMPUTE_PORT`, `F7T_RESERVATIONS_PORT`, `F7T_STATUS_PORT`, `F7T_STORAGE_PORT`, `F7T_TASKS_PORT`, `F7T_UTILITIES_PORT` | no | 5000 | port to run for each microservice, each service only requires its own. Also check `F7T_x_URL`|
`F7T_CERTIFICATOR_URL`, `F7T_COMPUTE_URL`, `F7T_RESERVATIONS_URL`, `F7T_STATUS_URL`, `F7T_STORAGE_URL`, `F7T_TASKS_URL`,  `F7T_UTILITIES_URL` | yes | | Used internally by microservices to communicate to each other. Status uses `F7T_<service>_URL` to query them. Depending on network configuration, they may match internal URLs defined on Kong configuration|
|`F7T_DEBUG_MODE` | no | False ||
|`F7T_LOG_PATH`   | no | /var/log ||
|`F7T_LOG_TYPE`   | no | file | Valid values are 'file' and 'stdout' |
|`F7T_UTILITIES_MAX_FILE_SIZE` | no | 5 | In megabytes, used by Compute and Utilities file upload|
|`F7T_UTILITIES_TIMEOUT`       | no | 5 | In seconds, timeout for synchronous commands|
|`F7T_STATUS_SERVICES` | yes | | List of services Status will query/report|
|`F7T_PERSISTENCE_IP`, `F7T_PERSIST_PORT`, `F7T_PERSIST_PWD`| yes | | IP, port and password to connect to Redis (required only by Tasks)|

### 1.4. Gunicorn configuration
| **Name** | **Required** | **Default value** | **Notes** |
| -------- | -----------  | ----------------- | --------- |
|`F7T_GUNICORN_LOG`   | no | `--error-logfile ${F7T_LOG_PATH}/<service>.gunicorn.log` | Set to empty for stdout output |
|`F7T_GUNICORN_SSL`   | no | `--ciphers TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_128_GCM_SHA256,DHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-AES128-GCM-SHA256 --ssl-version TLSv1_2 --keyfile $F7T_SSL_KEY --certfile $F7T_SSL_CRT` ||
|`F7T_GUNICORN_WORKER` | no | `--workers=1 --threads=1` ||


## 2. Site/cluster integration

### 2.1. IAM integration
| **Name** | **Required** | **Default value** | **Notes** |
| -------- | -----------  | ----------------- | --------- |
|`F7T_REALM_RSA_PUBLIC_KEY` | | None | If not defined, no check is performed on the JWT. Can be a list. See note **(b)**|
|`F7T_REALM_RSA_TYPE` | maybe | None | Required if `F7T_REALM_RSA_PUBLIC_KEY` is defined|
|`F7T_AUTH_ROLE` | | None | If defined it must be present in JWT `["realm_access"]["roles"]` list|
|`F7T_OPA_USE`   | | False | |
|`F7T_OPA_URL`   | | `http://localhost:8181` | |
|`F7T_POLICY_PATH`   | | `v1/data/f7t/authz` | |

### 2.2. Clusters and internal machines
| **Name** | **Required** | **Default value** | **Notes** |
| -------- | -----------  | ----------------- | --------- |
|`F7T_SYSTEMS_PUBLIC` | yes | | list of cluster public names (as seen by users)|
|`F7T_SYSTEMS_INTERNAL_COMPUTE` | yes | | list of internal machines where Slurm commands are executed (see note c)|
|`F7T_SYSTEMS_INTERNAL_STORAGE`| yes | | list of internal machines where Storage commands are executed (see note c)|
|`F7T_SYSTEMS_INTERNAL_UTILITIES`| yes | | list of internal machines where Utilities commands are executed (see note c)|


### 2.3. Object Storage (credential, account, properties)
| **Name** | **Required** | **Default value** | **Notes** |
| -------- | -----------  | ----------------- | --------- |
|`F7T_OBJECT_STORAGE` | | None | OS name, supported values: `swift`, `s3v2`, `s3v4`|
|`F7T_OS_AUTH_URL`, `F7T_OS_IDENTITY_PROVIDER`, `F7T_OS_PROTOCOL`, `F7T_OS_PROJECT_ID`, `F7T_OS_CLIENT_ID`, `F7T_OS_CLIENT_SECRET`, `F7T_OS_DISCOVERY_ENDPOINT` | | | Keystone SAML and OIDC support|
|`F7T_OS_KEYSTONE_AUTH` | | None | Keystone auth method, supported values: `oidc`, `saml`, `''`|
|`F7T_SWIFT_PRIVATE_URL`, `F7T_SWIFT_PUBLIC_URL`, `F7T_SWIFT_API_VERSION`, `F7T_SWIFT_ACCOUNT`, `F7T_SWIFT_USER`, `F7T_SWIFT_PASS` | maybe | | 	Required if `F7T_OBJECT_STORAGE='swift'`|
|`F7T_S3_PRIVATE_URL`, `F7T_S3_PUBLIC_URL`, `F7T_S3_ACCESS_KEY`, `F7T_S3_SECRET_KEY` | maybe | | Required if `F7T_OBJECT_STORAGE='s3v2'` or `s3v4`|
`F7T_STORAGE_POLLING_INTERVAL`|  | 60 | In secods, polling interval to OS to check which upload_files is downloadable to file system|


### 2.3.4. Gateway (Kong)
| **Name** | **Required** | **Default value** | **Notes** |
| -------- | -----------  | ----------------- | --------- |
|`F7T_KONG_URL` | Yes |  | Public base URL returned to the user for async operations, not used internally|


### 2.3.5. Tracing (Jaeger)
| **Name** | **Required** | **Default value** | **Notes** |
| -------- | -----------  | ----------------- | --------- |
|`F7T_JAEGER_AGENT` | | None | Jaeger agent IP, port is fixed to 6831





Notes:
a. Variable `F7T_SYSTEMS_PUBLIC` has a list of public names seen by client/user. Internal variables  `F7T_SYSTEMS_INTERNAL_COMPUTE`, `F7T_SYSTEMS_INTERNAL_UTILITIES`, `F7T_USE_SPANK_PLUGIN`, `F7T_COMPUTE_BASE_FS`, `F7T_STORAGE_JOBS_MACHINE` must have the same order and length, matching to internal URIs/options. Example: for `F7T_SYSTEMS_PUBLIC='publicName1;publicName2'`  then `F7T_SYSTEMS_INTERNAL_COMPUTE='172.16.1.2:22;compute2:2022'`
b. `F7T_REALM_RSA_PUBLIC_KEY`  has the RSA public key from Keycloak realm (or other OIDC provider). It's is used to validate JWT tokens included on requests (via 'Authorization' header). If empty, no verification is made on the token, which is only useful for debugging. Additionally, if not running in debug mode (`F7T_DEBUG_MODE`) microservices will log a warning. As some systems are tricky with variables containing multiple lines,  use only one line without headers (`-----BEGIN PUBLIC KEY-----`, `-----END PUBLIC KEY-----`), they'll be added by F7T. This variable and related ones are static so microservices do not need to contact the OIDC server.
c. All lists are semi colon separated. Single and double quotes are removed from start and end of all variables.
