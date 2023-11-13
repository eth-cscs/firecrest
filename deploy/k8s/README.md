# Kubernetes deployment with Helm

## Before deploying
Helm only allows to include files inside the chart directory. To install the 'openapi' chart (SwaggerUI) it is required to make symlink to the OpenAPI specification

`ln -s ../../../../doc/openapi/firecrest-api.yaml openapi/files/firecrest-api.yaml`
