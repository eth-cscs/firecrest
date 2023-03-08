# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
