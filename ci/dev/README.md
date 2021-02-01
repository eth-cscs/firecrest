# FirecREST Testing

## Requirements

You can run the tests on any linux machine with...

- [bash](https://www.gnu.org/software/bash/) >= `4` (with sudo)
- [docker](https://docs.docker.com/engine/install/) >= `20.10.1`
- [docker-compose](https://docs.docker.com/compose/install/) >= `1.26.2`

## Usage

Clone this repo and cd into it...

```
git clone https://github.com/eth-cscs/firecrest
cd firecrest
```

To run all tests for the first time simply run...

```
ci/dev/run.sh
```

Have a look at that script. It will setup and build everything from the scratch and run ALL the dev tests.

If you have already setup everything and just want to re-run some tests without recreating everything
from the scratch, you can call the scripts that `ci/dev/test.sh` is calling.

```
ci/dev/test.sh
```

## Debugging

If you want to re-test something specific, you can customize the docker calls of the end of `ci/dev/tests.sh`
to make an ad-hoc pytest call.

If the stdout information is not enough, remember to check either the logs in the logs folder created in `ci/dev/setup.sh`
or the container logs with [docker logs](https://docs.docker.com/engine/reference/commandline/logs/).