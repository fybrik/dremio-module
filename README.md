# DremioModule

### Install fybrik
Fybrik Quick Start (v0.6), without the section of `Install modules`.

### Register the fybrikmodule:
```bash
kubectl apply -f dremio-module.yaml -n fybrik-system
```

### Create namespace
```bash
kubectl create namespace fybrik-notebook-sample
kubectl config set-context --current --namespace=fybrik-notebook-sample
```

### Register asset and secret
```bash
kubectl apply -f sample_assets/asset-iceberg.yaml -n fybrik-notebook-sample
```
Replace the values for access_key and secret_key in `sample_asset/secret-iceberg.yaml` file with the values from the object storage service that you used and run:
```bash
kubectl apply -f sample_assets/secret-iceberg.yaml -n fybrik-notebook-sample
```

### Define data access policy
An example policy of remove columns.
```bash
kubectl -n fybrik-system create configmap sample-policy --from-file=sample_assets/sample-policy.rego
kubectl -n fybrik-system label configmap sample-policy openpolicyagent.org/policy=rego
while [[ $(kubectl get cm sample-policy -n fybrik-system -o 'jsonpath={.metadata.annotations.openpolicyagent\.org/policy-status}') != '{"status":"ok"}' ]]; do echo "waiting for policy to be applied" && sleep 5; done
```

### Deploy Fybrik application which triggers the module
```bash
kubectl apply -f fybrikapplication.yaml -n default
```
Run the following command to wait until the fybrikapplication be ready.
```bash
while [[ $(kubectl get fybrikapplication my-notebook -n default -o 'jsonpath={.status.ready}') != "true" ]]; do echo "waiting for FybrikApplication" && sleep 5; done
```
There should be four running pods in `fybrik-blueprints` namespace.
Wait For the pod `my-notebook-default-dremio-module-xxxx` to be completed. This pod runs a python code that registers the asset in dremio and applies the policy to create a virtual dataset. The user can use the following credentials to connect to Dremio:

    "name": "newUser", 
    "password": "testpassword123"


