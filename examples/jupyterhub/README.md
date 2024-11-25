# FirecRESTSpawner on the Docker demo


This tutorial explains how to run [JupyterHub](https://jupyterhub.readthedocs.io/en/stable/) with [FirecRESTSpawner](https://github.com/eth-cscs/firecrestspawner) using the [Docker demo of FirecREST](https://github.com/eth-cscs/firecrest/tree/master/deploy/demo).

FirecRESTSpawner is a tool for launching Jupyter Notebook servers from JupyterHub on HPC clusters through [FirecREST](https://firecrest.readthedocs.io/en/stable/).
It can be deployed on Kubernetes as part of JupyterHub and configured to target different systems.

In this tutorial, we will set up a simplified environment on a local machine, including:

- a [Docker Compose](https://docs.docker.com/compose) deployment of FirecREST, a single-node Slurm cluster and a [Keycloak](https://www.keycloak.org) server which will be used as identity provider for the authentication
- a local installation of JupyterHub, configured to launch notebooks on the Slurm cluster

This deployment not only demonstrates the use case but also serves as a platform for testing and developing FirecRESTSpawner.


## Requirements

For this tutorial you will need

 * a recent installation of Docker, which includes the `docker compose` command (or the older `docker-compose` command line tool)
 * a Python installation (version 3.9 or higher)


## Setup


### Building images from FirecREST's Docker Compose demo

This tutorial builds on the Docker demo of FirecREST.
We will use a small [docker-compose.yaml](docker-compose.yaml) file to override some settings in the FirecREST demo.
This can be done by passing both files to the `docker compose` command.

To get started, let's clone the FirecREST repository

```bash
git clone https://github.com/eth-cscs/firecrest.git
```

and build the images used in it's [Docker Compose demo](https://github.com/eth-cscs/firecrest/tree/master/deploy/demo):

```bash
cd firecrest/deploy/demo/
docker compose build
```

This step takes a few minutes. In the meanwhile we can install JupyterHub on a local virtual environment.


### Install JupyterHub and FirecRESTSpawner

An easy way to install JupyterHub is via [Miniconda](https://docs.anaconda.com/miniconda/install/).
We need to [download the Miniconda installer](https://docs.anaconda.com/miniconda/install/) for our platforms and install it using the following command

```bash
bash Miniconda3-latest-<arch>.sh -p /path/to/mc-jhub -b
```

Here we use `-p` to pass the absolute path to the install directory and `-b` to accept the [terms of service](https://legal.anaconda.com/policies/en/).

We can activate our conda base environment and install configurable-http-proxy, JupyterHub and FirecRESTSpawner

```bash
. /path/to/mc-jhub/bin/activate
conda install -y configurable-http-proxy
pip install --no-cache jupyterhub==4.1.6 pyfirecrest==2.6.0 SQLAlchemy==1.4.52 oauthenticator==16.3.1 python-hostlist==1.23.0

git clone https://github.com/eth-cscs/firecrestspawner.git
cd firecrestspawner
pip install --no-cache .
```

## Deployment of FirecREST and Slurm cluster

Once all the images have been built we can move to the tutorial directory and deploy the [docker-compose.yaml](docker-compose.yaml).

```bash
cd firecrest/examples/jupyterhub 
export JHUB_DOCKERFILE_DIR=$PWD
docker compose -f ../../deploy/demo/docker-compose.yml -f docker-compose.yml up --build
```

This step will create a new image that extends the `f7t-cluster` image from the Docker demo of FirecREST to include JupyterLab and other requirements.
The process may take a few minutes, as some dependencies for JupyterLab need to be built from source.

Once that's finished, you can check that all containers are running

```bash
docker compose -p demo ps --format 'table {{.ID}}\t{{.Name}}\t{{.State}}'
```

That should show something like this

```bash
CONTAINER ID   NAME              STATE
fa355219633c   certificator      running
8dada9a2f57a   cluster           running
bd5f33b3b34e   compute           running
8b8029c9bec2   fckeycloak        running
e66970df55a8   jaeger            running
1be08e3707f4   kong              running
9dd5a68a84b0   minio             running
33ce4e9df9c5   opa               running
b0cfba2eb816   openapi           running
974356ee229a   reservations      running
143375c02912   status            running
c424bca5efef   storage           running
5004cc49e1b8   taskpersistence   running
163d91b0bd8d   tasks             running
5239294e62bb   utilities         running
```

When we are done with the tutorial, the deployment can be shutdown by pressing `ctrl+c` and then

```
cd firecrest/examples/jupyterhub
docker compose -f ../../deploy/demo/docker-compose.yml -f docker-compose.yml down
```

### Setting up the authorization

A requirement for running JupyterHub with FirecRESTSpawner is to use an authenticator that prompts users for login and password in exchange for an access token.
That token is then be passed to the spawner, allowing users to authenticate with FirecREST when submitting, stopping or polling for jobs.
For this purpose, we will use an Authorization Code Flow client, which we need to create on the Keycloak web interface.

Let's go to the [Clients page](http://localhost:8080/auth/admin/master/console/#/realms/kcrealm/clients) in Keycloak (username: admin, password: admin2) within the `kcrealm` realm.
We click on "Create" and then on "Select file".
A file system explorer will open.
Navigate to the tutorial's directory, choose the [jhub-client.json](jhub-client.json) file and click on "Save".

Once that's done, the client `jhub-client` can be seen listed on the "Clients" tab of the side panel.


### Launching JupyterHub

The [configuration file](jupyterhub-config.py) provided in this tutorial has all the settings needed for using JupyterHub with our deployment.
Depending on the platform and Docker setup, you may need to adjust a few lines in the configuration to set the correct host IP address for the Docker bridge network. On most Linux systems, you can find this address with `ip addr show docker0`. It is typically `172.17.0.1`, which you can use to replace `host.docker.internal` in the configuration if the latter doesn't work.

Now we can run JupyterHub with

```bash
. /path/to/mc-jhub/bin/activate
. env.sh 
jupyterhub --config jupyterhub-config.py --port 8003 --ip 0.0.0.0
```
Here we are sourcing the file [env.sh](env.sh) which defines environment variables needed by the spawner (more information can be found [here](https://firecrestspawner.readthedocs.io/en/latest/authentication.html)).
We use the port `8003` for the JupyterHub since the default one `8000` is already used for FirecREST in the deployment.
The ip `0.0.0.0` is necessary to allow JupyterLab to connect back to the JupyterHub.

JupyterHub should be accessible in the browser at [http://localhost:8003](http://localhost:8003/) (username: test1 and password: test11) and it should be possible to launch notebooks on the slurm cluster.
