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

### Deploy Fybrik application
```bash
kubectl apply -f fybrikapplication.yaml -n default
```
Wait for the fybrik module:
```bash
while [[ ($(kubectl get fybrikapplication my-notebook -n default -o 'jsonpath={.status.ready}') != "true") || ($(kubectl get jobs my-notebook-default-dremio-module -n fybrik-blueprints -o 'jsonpath={.status.conditions[0].type}') != "Complete") ]]; do echo "waiting for FybrikApplication" && sleep 5; done
```

Use port-forward to access Dremio
```
kubectl port-forward svc/dremio-client -n fybrik-blueprints 9047:9047 &
```

Send a SQL query to the module:
```
python query_sample.py --query '{"sql": "<query>"}'
```
For the `FROM` clause use `FROM \"Space-api\".\"sample-iceberg-vds\"`.

You can also access Dremio via the browser on `http://localhost:9047/`, use the following credentials:
    "name": "newUser", 
    "password": "testpassword123"


