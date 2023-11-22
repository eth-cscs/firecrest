# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.14.0]

### Added

- Add constraint in xfer-internal job script when provided by the configuration. The associated environment variable is `F7T_XFER_CONSTRAINT` and can be empty, when no machine needs it. Otherwise, the different constraints should be separated by `;`.
- Support passing environment variables when submitting a job.
- Support listing directories without resolving UID/GID.
- Add description for each parameter in `GET /status/parameters` response.
- Add support for Object Storage Tenants in S3v4 object storage. The associated environment variable is `F7T_S3_TENANT` and it can be empty or be `null` or `none` when the tenant is not needed. Otherwise the tenant name has to be set.

## Changed

- CI/CD pipeline is now adapted to create helm charts images and push to a repository when TDS or Prod are tagged
  - Also secrets now can be managed from ExternalSecrets on K8s deployment
  - Deployment on TDS triggers ArgoCD deployment
- Demo and k8s deployments have the Swagger UI API specification at unauthenticated `/docs` endpoint

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
