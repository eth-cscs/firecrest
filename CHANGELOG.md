# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [1.13.1]

### Added

- Tasks microservice now provides filtering by a subset of tasks with a `tasks` parameter
  - `GET /tasks?tasks=<taskid>,<taskid>,<taskid>`



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

### Changed

- Allow square brackets in user input.
- `/utilities/stat` endpoint now uses `%f` to return file type and permissions in `mode` field.

### Fixed

- Return the `X-Exists` header for existing folders in `/utilities/mkdir`, instead of `X-A-Directory`.
- Fix bug on view endpoint. Return normally the files that included error messages.
