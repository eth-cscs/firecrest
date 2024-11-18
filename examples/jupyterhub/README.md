# FirecRESTSpawner on the Docker demo


This is a tutorial on how to run JupyterHub with [FirecRESTSpawner](https://github.com/eth-cscs/firecrestspawner) on the [Docker demo of FirecREST](https://github.com/eth-cscs/firecrest/tree/master/deploy/demo).

We are going to start by deploying FirecREST together with a slurm cluster using [Docker Compose](https://docs.docker.com/compose). Then we will install JupyterHub on a virtual environment and configure it to launch notebooks on the slurm cluster via FirecREST.


## Requirements

For this tutorial it's necessary
 * a recent installation of Docker, which includes the `docker compose` command. Alternatively the old `docker-compose` command line could be used.
 * a python installation (`>=3.9`)


## Setup


### Building images from FirecREST's Docker Compose demo

The `docker-compose.yaml` that we use in this the demo is a copy of the the one used in the Docker demo of FirecREST with only a few small changes. So, to get started, let's clone the FirecREST repository

```bash
git clone https://github.com/eth-cscs/firecrest.git
cd firecrest/deploy/demo/
```

and build the images used in it's [Docker Compose demo](https://github.com/eth-cscs/firecrest/tree/master/deploy/demo):

```bash
docker compose build
```

This step is going to last a few minutes. In the meanwhile we can install JupyterHub on a virtual environment on our machine.


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

## Deployment of the FirecREST and Slurm cluster

Once all the images have been built we can move to the JupyterHub demo directory and start deploy the [`docker-compose.yaml`](docker-compose.yaml).

```bash
cd firecrest/examples/jupyterhub 
docker compose up -d --build
```

The deployment can be shutdown with

```
cd firecrest/examples/jupyterhub
docker compose down
```

### Setting up the authorization

To login on JupyterHub and authenticate with FirecREST in the spawner, we need to create an Authorization Code Flow client in the `kcrealm` in Keycloak. In [this page](http://localhost:8080/auth/admin/master/console/#/realms/kcrealm/clients) (username: admin, password: admin2), click on "Create" and then on "Select file" choose the [`jhub-client.json`](jhub-client.json) file from the file system.

Once that's done, the client `jhub-client` can be seen listed on the "Clients" tab.


### Launching JupyterHub

The configuration file provided [here](jupyterhub-config.py) has all the setting to use JupyterHub with the our deployment, but the secret for the client we just created must be added on `c.Authenticator.client_secret`. The secret can be found in the client's ["Credentials" tab](http://localhost:8080/auth/admin/master/console/#/realms/kcrealm/clients/f969b69d-4aec-4646-bdbe-09a268f52111/credentials).

JupyterHub can be run with

```bash
. jhub-env/bin/activate
. env.sh 
jupyterhub --config jupyterhub-config.py --port 8003 --ip 0.0.0.0 --debug
```
Here we are sourcing the file [`env.sh`](env.sh) which defines environment variables needed by the spawner.
We use the port `8003` for the hub since `8000` is already used for FirecREST itself in the demo deployment. The ip `0.0.0.0` is necessary to allow JupyterLab to connect back to the hub.

The hub should be accessible in the browser at [http://localhost:8003](http://localhost:8003/) (username: test1 and password: test11) and you should be able to submit notebook jobs.
