# FirecREST demo

This demo uses [Docker Compose](https://docs.docker.com/compose/install/) to setup containers for FirecREST microservices, a template client, Keycloak, Kong, Redis, Minio and a dummy cluster with Slurm.

## Quick start

First, build components:

`docker-compose build`

The "cluster" container first time build may take some minutes because it compiles Slurm from source.

SSH private keys (`ca-key` and `user-key`) must be readable only by its owner on host machine. These keys are shared with the test setup. Please make sure private keys permissions are '400' before starting containers:

`chmod 400 ../test-build/environment/keys/ca-key  ../test-build/environment/keys/user-key`


To start containers:

`docker-compose up`

Then, go to `http://localhost:7000`  User is `test1` and password is `test11`


To stop all containers:

`docker-compose down`



## Notes for customization:

- To test with another cluster/server, change on `common/common.env` the list of systems (*SYSTEMS_*) and *STATUS_SYSTEMS*; and on `demo_client/config.py` change *MACHINES*. Also add a volume on Certificator's service inside `docker-compose.yml` pointing to your server's SSH CA private key.

- FirecREST source is read from `src/` with Dockerfiles from `deploy/docker`. Client source is on `src/tests/template_client/` and has a Dockerfile, configuration for this demo is read from `deploy/demo/demo_client/`. Most of the configuration is on `deploy/demo/common/common.env` and additional variables are set inside `deploy/demo/docker-compose.yml`

- Keycloak configuration is loaded from `keycloak/config.json`. Use `admin`:`admin2` to access administration console on `http://localhost:8080`

- Kong configuration is loaded from `kong/kong.yml`. If you change a FirecREST's service URL, you need to update `common/common.env` and that file, or run `deploy/demo/source/kong/update_kong_config.sh`

- Minio configuration is set on `docker-compose.yml` for *Storage* and *Minio* services.

- Redis configuration is loaded from `taskpersistence/resdis.conf` and must match *Tasks* service configuration.

- To add or change a component, it's possible to disable it from "docker-compose.yml" and create a new file which uses the same network. This way, only that component needs to be rebuild and restarted.

- To rebuild and restart only containers that haver changed:

`docker-compose up -d --build`

`docker-compose restart <service>`



## Debugging:

Logs are stored on `logs/` for microservices and most services, Minio staging area on `minio/`, and  *Task persistence* data (Redis) on `taskpersistence-data/`. Please note that staging area data is deleted after a successful upload to the cluster, but downloaded files aren't deleted soon.
