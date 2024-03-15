#Local k8s Demo Cluster


## Requirements

### Heml

Install on macOS:
```console
brew install helm
```

### Hemlfile
On Desktop the cluster deployment is operated by helmfile, a lightweight solution similar to ArgoCD.
```console
brew install helmfile
```

### Docker registry
Install local registry
```console
docker run -d -p 5000:5000 --name registry registry:latest
```

Push required images to local registry
```console
docker tag f7t-compute  localhost:5000/compute:latest
docker push localhost:5000/compute:latest

docker tag f7t-cluster  localhost:5000/cluster:latest
docker push localhost:5000/cluster:latest

docker tag f7t-certificator localhost:5000/certificator:latest
docker push localhost:5000/certificator:latest

docker tag f7t-status localhost:5000/status:latest
docker push localhost:5000/status:latest

docker tag f7t-storage localhost:5000/storage:latest
docker push localhost:5000/storage:latest

docker tag f7t-tasks localhost:5000/tasks:latest
docker push localhost:5000/tasks:latest

docker tag f7t-utilities localhost:5000/utilities:latest
docker push localhost:5000/utilities:latest

```

### Start Local Cluster
```console
helmfile sync helmfile.yaml
```

### Destroy Local Cluster
```console
helmfile delete helmfile.yaml
```