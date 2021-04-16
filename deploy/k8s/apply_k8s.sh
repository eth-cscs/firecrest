#!/bin/bash

echo "* Deleting services..."
kubectl delete all --all

echo
echo "* Starting k8s..."
kubectl apply -f . -R

echo
echo "* Forwarding ports for Keycloak and Kong (use 'jobs' to view)... "

k1=$(kubectl get pods | grep ^deploy-kong)
while [ "$k1" == "" ]; do
   sleep 1;
   k1=$(kubectl get pods | grep ^deploy-kong)
done

k1=${k1%% *}
kubectl port-forward ${k1} 8000:8000 &> /dev/null &
k1=$(kubectl get pods | grep ^deploy-keycloak)
k1=${k1%% *}
kubectl port-forward ${k1} 8080:8080 &> /dev/null &


