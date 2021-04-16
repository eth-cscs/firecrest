#!/bin/bash

wait_running() {
  echo " ... waiting for $1"
  k1=$(kubectl get pods | grep ^deploy-$1 | grep Running)
  while [ "$k1" == "" ]; do
    sleep 1;
    k1=$(kubectl get pods | grep ^deploy-$1 | grep Running)
  done
  pod=${k1%% *}
}


echo "* Deleting services..."
kubectl delete all --all

echo "* Killing port forwardings..."
pkill -f "kubectl port-forward deploy-"

echo
echo "* Starting k8s..."
kubectl apply -f . -R

echo "* Doing port forwardings..."
pod=""
wait_running kong
kubectl port-forward $pod 8000:8000 &> /dev/null &
p="$!"

wait_running keycloak
kubectl port-forward $pod 8080:8080 &> /dev/null &
p="$p $!"

wait_running minio
kubectl port-forward $pod 9000:9000 &> /dev/null &
p="$p $!"
echo "... all done, to kill forward processes: kill $p"
