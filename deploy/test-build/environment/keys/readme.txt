Notes:
- ca-key: only required by Certificator microservice. On startup, it sets permissions 400 to avoid security warnings
- ca-key.pub: only required by Cluster container
- user-key: required by microservies that connect to clusters: Compute, Storage, Utilities
- user-key.pub: required by Certificator to issue certificates
