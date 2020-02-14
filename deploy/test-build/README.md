Notes:

Two sets of SSH keys are provided for testing:
- ca-key: only required by Certificator microservice. On startup, it checks permissions to be '400' to work properly
- ca-key.pub: only required by Cluster container
- user-key: required by microservies that connect to clusters: Compute, Storage, Utilities
- user-key.pub: required by Certificator to issue certificates

SSH private keys ('ca-key' and 'user-key') must be readable only owner on host machine. Please set private keys permissions 
to 400 before starting containers:

`chmod 400 environment/keys/ca-key  environment/keys/user-key`

This keys are used by the demo environment also.
