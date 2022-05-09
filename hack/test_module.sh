#!/usr/bin/env bash
# Copyright 2020 IBM Corp.
# SPDX-License-Identifier: Apache-2.0

set -x
set -e

source ./tools/common.sh

export WORKING_DIR=test-script
export ACCESS_KEY=1234
export SECRET_KEY=1234
export TOOLBIN=tools/bin

# usage: <kubernetes version> <fybrik version> <module version>

kubernetesVersion=$1
fybrikVersion=$2
moduleVersion=$3
certManagerVersion=$4
expectedOutputVersion=$5

# Trim the last two charts of the module version
# to construct the module resource path
moduleResourceVersion=${moduleVersion%??}".0"

if [ $kubernetesVersion == "kind19" ]
then
    ${TOOLBIN}/kind delete cluster
    ${TOOLBIN}/kind create cluster --image=kindest/node:v1.19.11@sha256:07db187ae84b4b7de440a73886f008cf903fcf5764ba8106a9fd5243d6f32729
elif [ $kubernetesVersion == "kind20" ]
then
    ${TOOLBIN}/kind delete cluster
    ${TOOLBIN}/kind create cluster --image=kindest/node:v1.20.7@sha256:cbeaf907fc78ac97ce7b625e4bf0de16e3ea725daf6b04f930bd14c67c671ff9
elif [ $kubernetesVersion == "kind21" ]
then
    ${TOOLBIN}/kind delete cluster
    ${TOOLBIN}/kind create cluster --image=kindest/node:v1.21.1@sha256:69860bda5563ac81e3c0057d654b5253219618a22ec3a346306239bba8cfa1a6
elif [ $kubernetesVersion == "kind22" ]
then
    ${TOOLBIN}/kind delete cluster
    ${TOOLBIN}/kind create cluster --image=kindest/node:v1.22.0@sha256:b8bda84bb3a190e6e028b1760d277454a72267a5454b57db34437c34a588d047
else
    echo "Unsupported kind version"
    exit 1
fi


#quick start

${TOOLBIN}/helm repo add jetstack https://charts.jetstack.io
${TOOLBIN}/helm repo add hashicorp https://helm.releases.hashicorp.com
${TOOLBIN}/helm repo add fybrik-charts https://fybrik.github.io/charts
${TOOLBIN}/helm repo update

# https://cert-manager.io/docs/installation/supported-releases/
${TOOLBIN}/helm install cert-manager jetstack/cert-manager \
    --namespace cert-manager \
    --version v$certManagerVersion \
    --create-namespace \
    --set installCRDs=true \
    --wait --timeout 220s


${TOOLBIN}/helm install vault fybrik-charts/vault --create-namespace -n fybrik-system \
    --set "vault.injector.enabled=false" \
    --set "vault.server.dev.enabled=true" \
    --values https://raw.githubusercontent.com/fybrik/fybrik/v$fybrikVersion/charts/vault/env/dev/vault-single-cluster-values.yaml
${TOOLBIN}/kubectl wait --for=condition=ready --all pod -n fybrik-system --timeout=220s


${TOOLBIN}/helm install fybrik-crd fybrik-charts/fybrik-crd -n fybrik-system --version v$fybrikVersion --wait
${TOOLBIN}/helm install fybrik fybrik-charts/fybrik -n fybrik-system --version v$fybrikVersion --wait

${TOOLBIN}/kubectl wait --for=condition=ready --all pod -n fybrik-system --timeout=220s

# Related to https://github.com/cert-manager/cert-manager/issues/2908
# Fybrik webhook not really ready after "helm install --wait"
# A workaround is to loop until the module is applied as expected
CMD="${TOOLBIN}/kubectl apply -f https://github.com/fybrik/hello-world-read-module/releases/download/v$moduleVersion/hello-world-read-module.yaml -n fybrik-system"
count=0
until $CMD
do
  if [[ $count -eq 10 ]]
  then
    break
  fi
  sleep 1
  ((count=count+1))
done


# Notebook sample

${TOOLBIN}/kubectl create namespace fybrik-notebook-sample
${TOOLBIN}/kubectl config set-context --current --namespace=fybrik-notebook-sample

${TOOLBIN}/kubectl apply -f https://raw.githubusercontent.com/fybrik/hello-world-read-module/releases/$moduleVersion/sample_assets/assetMedals.yaml -n fybrik-notebook-sample
${TOOLBIN}/kubectl apply -f https://raw.githubusercontent.com/fybrik/hello-world-read-module/releases/$moduleVersion/sample_assets/secretMedals.yaml -n fybrik-notebook-sample
${TOOLBIN}/kubectl apply -f https://raw.githubusercontent.com/fybrik/hello-world-read-module/releases/$moduleVersion/sample_assets/assetBank.yaml -n fybrik-notebook-sample
${TOOLBIN}/kubectl apply -f https://raw.githubusercontent.com/fybrik/hello-world-read-module/releases/$moduleVersion/sample_assets/secretBank.yaml -n fybrik-notebook-sample


${TOOLBIN}/kubectl -n fybrik-system create configmap sample-policy --from-file=$WORKING_DIR/sample-policy-$moduleResourceVersion.rego
${TOOLBIN}/kubectl -n fybrik-system label configmap sample-policy openpolicyagent.org/policy=rego
c=0
while [[ $(${TOOLBIN}/kubectl get cm sample-policy -n fybrik-system -o 'jsonpath={.metadata.annotations.openpolicyagent\.org/policy-status}') != '{"status":"ok"}' ]]
do
    echo "waiting"
    ((c++)) && ((c==25)) && break
    sleep 5
done

${TOOLBIN}/kubectl apply -f https://raw.githubusercontent.com/fybrik/hello-world-read-module/releases/$moduleVersion/fybrikapplication.yaml -n default

c=0
while [[ $(${TOOLBIN}/kubectl get fybrikapplication my-notebook -n default -o 'jsonpath={.status.ready}') != "true" ]]
do
    echo "waiting"
    ((c++)) && ((c==30)) && break
    sleep 6
done

${TOOLBIN}/kubectl get pods -n fybrik-blueprints

POD_NAME=$(${TOOLBIN}/kubectl get pods -n fybrik-blueprints -o=name | sed "s/^.\{4\}//")

${TOOLBIN}/kubectl logs ${POD_NAME} -n fybrik-blueprints > res.out

DIFF=$(diff $WORKING_DIR/expected-$expectedOutputVersion.txt res.out)
RES=0
if [ "${DIFF}" == "" ]
then
    echo "test succeeded"
else
    RES=1
fi

${TOOLBIN}/kubectl delete namespace fybrik-notebook-sample
${TOOLBIN}/kubectl -n fybrik-system delete configmap sample-policy

if [ ${RES} == 1 ]
then
  echo "test failed"
  exit 1
fi
