# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.16.0]

### Added

- Addded the endpoints `/compute/nodes` and `/compute/nodes/{nodeName}` to retrieve information about nodes in the scheduling queue.
- Added endpoints `POST /utilities/compress`, `POST /utilities/extract`, `POST /storage/xfer-internal/compress` and `POST /storage/xfer-internal/extract` for file compression and extraction.
- Added recurisive option to ls utilities command `&recursive=true`.
- Added the endpoints `/compute/partitions` and `/compute/partitions/{partitionName}` to retrieve information about partitions in the scheduling queue.
- Added grep support for tail and head command. `&grep=pattern`
- Added `examples` directory for practical use cases of FirecREST.

### Changed

- Environment variable names
  - Added: `F7T_CERTIFICATOR_HOST`, `F7T_COMPUTE_HOST`, `F7T_RESERVATION_HOST`, `F7T_STATUS_HOST`, `F7T_STORAGE_HOST`, `F7T_TASKS_HOST`, `F7T_UTILITIES_HOST`
  - Replaced
    - `F7T_SYSTEMS_PUBLIC` by `F7T_SYSTEMS_PUBLIC_NAME`
    - `F7T_USE_SSL` by `F7T_SSL_ENABLED`
    - `F7T_POLICY_PATH` by `F7T_OPA_POLICY_PATH`
    - `F7T_PERSISTENCE_IP` by `F7T_PERSIST_HOST`
    - `F7T_SSH_CERTIFICATE_WRAPPER` by `F7T_SSH_CERTIFICATE_WRAPPER_ENABLED`
    - `F7T_STATUS_SYSTEMS` by `F7T_SYSTEMS_INTERNAL_STATUS_ADDR`
    - `F7T_SECRET_KEY` by `F7T_SWIFT_SECRET_KEY`
    - `F7T_USE_SPANK_PLUGIN` by `F7T_SPANK_PLUGIN_ENABLED`

  - Removed: `F7T_CERTIFICATOR_URL`, `F7T_COMPUTE_URL`, `F7T_RESERVATION_URL`, `F7T_STATUS_URL`, `F7T_STORAGE_URL`, `F7T_TASKS_URL`, `F7T_UTILITIES_URL`, and `F7T_SWIFT_ACCOUNT` (it's using the same value than `F7T_OS_PROJECT_ID`)

- On task response metadata, the `task_url` value is now relative to the `/tasks` endpoint

### Fixed

- Fixed error on pipeline when releasing production version.
- Fixed response in task after timeout in one of the commands.
- Handle `ChunkedEncodingError` error in task creation to avoid crashing and returning 500 Error.

## [1.15.0]

### Added

- Add the endpoints `GET /status/filesystems` and `GET /status/filesystems/<system>`, providing enhancement in terms of filesystem availability
- The endpoint `/utilities/whoami` adds the `boolean` parameter "`groups`" which set on `true` returns a dictionary with `uid`, `gid`, and `groups`
- Added the parameter `WORKLOAD_MANAGER` in `GET /status/parameters` to provide information on the resource and workload manager used for compute
- Add `F7T_LOG_TYPE` to select logging to files or stdout.
- Add `F7T_GUNICORN_LOG` for Gunicorn logs.
- Add profiling middleware.

### Changed

- Improved retrieval of tasks from persistence storage.
- Upgraded `kong` gateway to [v3.6.0](https://docs.konghq.com/gateway/changelog/#3600)
- Upgraded `cryptography`package to [v42.0.4](https://cryptography.io/en/latest/changelog/#v42-0-4)
- Upgraded `paramiko` package to [v3.4.0](https://github.com/paramiko/paramiko/tree/3.4.0)

### Fixed

- Fixed demo images dependency declarations preventing docker-compose to build successfully.
- Fixed check when submitted an empty batch file on `POST /compute/jobs/upload`
- Fixed error message when `GET /status/systems` encounters error in one filesystem
- Fixed SSH connection error catching
- Fixed secured "ssh-keygen" command execution

## [1.14.0]

### Added

- Add constraint in xfer-internal job script when provided by the configuration. The associated environment variable is `F7T_XFER_CONSTRAINT` and can be empty, when no machine needs it. Otherwise, the different constraints should be separated by `;`.
- Support passing environment variables when submitting a job.
- Support listing directories without resolving UID/GID.
- Add description for each parameter in `GET /status/parameters` response.
- Add support for Object Storage Tenants in S3v4 object storage. The associated environment variable is `F7T_S3_TENANT` and it can be empty or be `null` or `none` when the tenant is not needed. Otherwise the tenant name has to be set.
- The task that is returned from a successful `GET /jobs/acct` would returns the attribute `time`, which is `cputime` from slurm. The attribute will remain and `cputime` and `elapsed` will be also returned. Similarly, `time_left` is actually the time of termination of the jobs. `time_left` will remain for compatibility reasons, but `elapsed` attribute will also be returned.
- Added `F7T_AUTH_ISSUER` to specify the JWT token issuer to be checked by Kong GW
- Removed `F7T_AUTH_REALM` and `F7T_AUTH_URL` which are no longer needed

### Changed

- CI/CD pipeline is now adapted to create helm charts images and push to a repository when TDS or Prod are tagged
  - Also secrets now can be managed from ExternalSecrets on K8s deployment
  - Deployment on TDS triggers ArgoCD deployment
- Demo and k8s deployments have the Swagger UI API specification at unauthenticated `/docs` endpoint

### Fixed

- Take into account `pageNumber` and `pageSize` arguments in `GET /compute/jobs` and `GET /compute/acct`.

## [1.13.1]

### Added

- Tasks microservice now provides filtering by a subset of tasks with a `tasks` parameter
  - `GET /tasks?tasks=<taskid>,<taskid>,<taskid>`

- Tasks microservice now reports in task metadata the system for which the task was created

- For storage tasks, now the `source` and `target` path are part of the `data` field on the response for all statuses

- For certificator container sets up the environment variables `F7T_CA_KEY_PATH` and `F7T_PUB_USER_KEY_PATH` as absolute paths in the container for the CA Private key (`ca-key`) and the user key (`user-key.pub`), respectively. If not set, the default directory will be root (ie, `/ca-key`)

- For the rest of microservices, the value to set is `F7T_PRIV_USER_KEY_PATH` (`user-key`)

- The `head` endpoint has a new argument: `skip_ending`. The output will be the whole file, without the last NUM bytes/lines of each file.

- The `tail` endpoint has a new argument: `skip_beginning`. The output will start with byte/line NUM of each file.

### Fixed

- Demo template UI client has been fixed in order to integrate latest changes
- Fixed correct header when the result of an operation in the system is `Not a directory` to `X-Not-A-Directory`
- Fixed the automatic change of the filename in uploaded files with empty spaces and other special characters.
- Fixed the issue with parsing `ls` when encountering filenames with the `$` character and whitespace.

## [1.13.0]

### Added

### Changed

- Flask version upgraded to `2.3.2`
- Cryptography version upgraded to `39.0.2`
- Certificator now uses `f7t-base` as base image

### Fixed

## [1.12.0]

### Added

- More tests for `/storage/xfer-external/upload` endpoint
### Changed

- For `/storage/xfer-external/upload` now is possible for the form parameter `targetPath` to be a file path or a directory path

### Fixed

- Upgrade to `redis == 4.5.4` in `tasks` API

## [1.11.1]

### Fixed

- Automated process for extracting the version number and using it in K8s OpenAPI pod

## [1.11.0]

### Added

- Add github workflow for automatic releases.
- Add new endpoints for `head` and `tail` commands.
- Add endpoint for the `whoami` command.
- Add `X-Size-Limit` to `/utilities/download` and `/utilities/view` endpoints API specification

### Changed

- Allow square brackets in user input.
- `/utilities/stat` endpoint now uses `%f` to return file type and permissions in `mode` field.

### Fixed

- Return the `X-Exists` header for existing folders in `/utilities/mkdir`, instead of `X-A-Directory`.
- Fix bug on view endpoint. Return normally the files that included error messages.
