# FirecREST demo

This demo uses [Docker Compose](https://docs.docker.com/compose/install/) to setup containers for FirecREST microservices, a template client, Keycloak, Kong, Redis, Minio and a dummy cluster with Slurm.

## Quick start

First, build components:

`docker-compose build`

The "cluster" container first time build may take some minutes because it compiles Slurm from source.

To start containers:

`docker-compose up`

Then, go to `http://localhost:7000`  User is `test1` and password is `test11`


To stop all containers:

`docker-compose down`



## Notes for customization:

- To add or change a component, it's possible to disable it from "docker-compose.yml" and create a new file which uses the same network. This way, only that component needs to be rebuild and restarted.

- To test with another cluster/server, change on `common/common.env` the list of systems (`SYSTEMS_*`) and `STATUS_SYSTEMS`; and on `demo_client/config.py` change `MACHINES`

- To rebuild and restart only containers that haver changed:

`docker-compose up -d --build`

`docker-compose restart <service>`



