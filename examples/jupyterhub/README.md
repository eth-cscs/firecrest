# FirecRESTSpawner on the Docker demo


This is a tutorial on how to run JupyterHub with [FirecRESTSpawner](https://github.com/eth-cscs/firecrestspawner) on the [Docker demo of FirecREST](https://github.com/eth-cscs/firecrest/tree/master/deploy/demo).

We are going to start by deploying FirecREST together with a slurm cluster using [Docker Compose](https://docs.docker.com/compose).
Then we will install JupyterHub on a virtual environment and configure it to launch notebooks on the slurm cluster via FirecREST.


## Requirements

For this tutorial it's necessary
 * a recent installation of Docker, which includes the `docker compose` command or the older `docker-compose` command line
 * a python installation (`>=3.9`)


## Setup


### Building images from FirecREST's Docker Compose demo

The [docker-compose.yaml](docker-compose.yaml) that we use in this the demo is a copy of the the one from the Docker demo of FirecREST with only a few small changes.
So, to get started, let's clone the FirecREST repository

```bash
git clone https://github.com/eth-cscs/firecrest.git
```

and build the images used in it's [Docker Compose demo](https://github.com/eth-cscs/firecrest/tree/master/deploy/demo):

```bash
cd firecrest/deploy/demo/
docker compose build
```

This step is going to take a few minutes. In the meanwhile we can install JupyterHub on a virtual environment on our machine.


### Install JupyterHub and FirecRESTSpawner

We can create a virtual environment

```bash
python -m venv jhub-env
```

and install JupyterHub and FirecRESTSpawner

```bash
. jhub-env/bin/activate

pip install --no-cache jupyterhub==4.1.6 pyfirecrest==2.6.0 SQLAlchemy==1.4.52 oauthenticator==16.3.1 python-hostlist==1.23.0

git clone https://github.com/eth-cscs/firecrestspawner.git
cd firecrestspawner
. jhub-env/bin/activate
pip install --no-cache .
```

## Deployment of FirecREST and Slurm cluster

Once all the images have been built we can move to the JupyterHub demo directory and deploy the [docker-compose.yaml](docker-compose.yaml).

```bash
cd firecrest/examples/jupyterhub 
docker compose up -d --build
```

This step will create a new image that extends the `f7t-cluster` image from the FirecREST demo to include JupyterLab and other requirements.
It will take some time since it needs to first build from source a few dependencies of JupyterLab.

Once the building is finished you can check that all containers are running

```bash
docker compose -p demo ps --format 'table {{.ID}}\t{{.Name}}\t{{.State}}'
# CONTAINER ID   NAME              STATE
# fa355219633c   certificator      running
# 8dada9a2f57a   cluster           running
# bd5f33b3b34e   compute           running
# 8b8029c9bec2   fckeycloak        running
# e66970df55a8   jaeger            running
# 1be08e3707f4   kong              running
# 9dd5a68a84b0   minio             running
# 33ce4e9df9c5   opa               running
# b0cfba2eb816   openapi           running
# 974356ee229a   reservations      running
# 143375c02912   status            running
# c424bca5efef   storage           running
# 5004cc49e1b8   taskpersistence   running
# 163d91b0bd8d   tasks             running
# 5239294e62bb   utilities         running
```

When we are done with the tutorial, the deployment can be shutdown with

```
cd firecrest/examples/jupyterhub
docker compose down
```

### Setting up the authorization

A requirement for running JupyterHub with FirecRESTSpawner is to use an authenticator that prompts users for login and password in exchange for an access token.
That token will then be passed to the spawner, allowing users to authenticate with FirecREST when submitting, stopping or polling for jobs.
For this purpose, we will use an Authorization Code Flow client, which we need to create on the Keycloak web interface.

Let's go to [this page](http://localhost:8080/auth/admin/master/console/#/realms/kcrealm/clients) (username: admin, password: admin2) and make sure that the top left side indicates that we are within the `Kcrealm` realm.
We click on "Create" and then on "Select file".
A file system explorer will open.
Navigate to the demo's directory and choose the [jhub-client.json](jhub-client.json) file.

Once that's done, the client `jhub-client` can be seen listed on the "Clients" tab of the side panel.


### Launching JupyterHub

The [configuration file](jupyterhub-config.py) provided in the demo has all the settings needed for using JupyterHub with our deployment.
We only need to add in `c.Authenticator.client_secret` the secret for the client we just created.
The secret can be found in the client's ["Credentials" tab](http://localhost:8080/auth/admin/master/console/#/realms/kcrealm/clients/f969b69d-4aec-4646-bdbe-09a268f52111/credentials).

Once that's done, JupyterHub can be run with

```bash
. jhub-env/bin/activate
. env.sh 
jupyterhub --config jupyterhub-config.py --port 8003 --ip 0.0.0.0 --debug
```
Here we are sourcing the file [env.sh](env.sh) which defines environment variables needed by the spawner(More information can be found [here](https://firecrestspawner.readthedocs.io/en/latest/authentication.html)).
We use the port `8003` for the hub since `8000` is already used for FirecREST itself in the demo deployment.
The ip `0.0.0.0` is necessary to allow JupyterLab to connect back to the hub.

The hub should be accessible in the browser at [http://localhost:8003](http://localhost:8003/) (username: test1 and password: test11) and it should be possible to launch notebooks on the slurm cluster.
