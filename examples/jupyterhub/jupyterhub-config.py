import secrets
from firecrestspawner.spawner import SlurmSpawner
from oauthenticator.generic import GenericOAuthenticator


def gen_hex_string(num_bytes=32, num_hex_strings=4):
    """Generate keys to encode the auth state"""
    hex_strings = [secrets.token_hex(num_bytes)
                   for i in range(num_hex_strings)]
    return hex_strings


c = get_config()

c.JupyterHub.authenticator_class = GenericOAuthenticator

# Keycloak setup
c.Authenticator.client_id = "jhub-client"
c.Authenticator.client_secret = "Ap45Agq2KpnbTXUGQxaUF1WiVOPm8Wf0"
c.Authenticator.oauth_callback_url = "http://localhost:8003/hub/oauth_callback"
c.Authenticator.authorize_url = "http://localhost:8080/auth/realms/kcrealm/protocol/openid-connect/auth"
c.Authenticator.token_url = "http://localhost:8080/auth/realms/kcrealm/protocol/openid-connect/token"
c.Authenticator.userdata_url = "http://localhost:8080/auth/realms/kcrealm/protocol/openid-connect/userinfo"
c.Authenticator.login_service = "http://localhost:8080"
c.Authenticator.username_claim = "preferred_username"
c.Authenticator.userdata_params = {"state": "state"}
c.Authenticator.scope = ["openid", "profile", "firecrest"]

# Hub access
c.Authenticator.admin_users = {"test1" }
c.Authenticator.allow_all = True

# Auth state enabled
c.Authenticator.enable_auth_state = True
c.CryptKeeper.keys = gen_hex_string()

c.JupyterHub.default_url = "/hub/home"

# Spawner setup
c.JupyterHub.spawner_class = SlurmSpawner
c.Spawner.req_host = "cluster"
c.Spawner.cmd = "firecrestspawner-singleuser jupyterhub-singleuser"
c.Spawner.enable_aux_fc_client = True
c.Spawner.node_name_template = "localhost"
c.Spawner.port = 56123
c.Spawner.batch_script = """#!/bin/bash
#SBATCH --job-name=jhub

export JUPYTERHUB_API_URL="http://host.docker.internal:8003/hub/api"
export JUPYTERHUB_ACTIVITY_URL="http://host.docker.internal:8003/hub/api/users/${USER}/activity"

export JUPYTERHUB_OAUTH_ACCESS_SCOPES=$(echo $JUPYTERHUB_OAUTH_ACCESS_SCOPES | base64 --decode)
export JUPYTERHUB_OAUTH_SCOPES=$(echo $JUPYTERHUB_OAUTH_SCOPES | base64 --decode)

export JUPYTERHUB_CRYPT_KEY=$(/usr/openssl1.1/bin/openssl rand -hex 32)

export PATH=/usr/openssl1.1/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

set -euo pipefail

. /opt/jhub-env/bin/activate

trap 'echo SIGTERM received' TERM
# {{prologue}}
{% if srun %}{{srun}}{% endif %} {{cmd}}
echo "jupyterhub-singleuser ended gracefully"
# {{epilogue}}
"""
