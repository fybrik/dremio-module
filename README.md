# DremioModule

### Install Fybrik
Fybrik Quick Start (v0.6), without the section of `Install modules`.

### Install Dremio (Optional)
You can install a Dremio cluster using the following command:
```bash
helm install <chart-name> dremio-chart/
```

### Register the fybrikmodule:
In `dremio-module.yaml` you can specify the host and port of an existing and running dremio cluster. If you installed a dremio cluster using the previous step you can set the dremio parameters in `dremio-module.yaml` as the following:
```
dremio.host: "dremio-client.<namespace of the dremio chart>.svc.cluster.local"
dremio.port: "9047"
```

Another option is to tell fybrik to start a dremio cluster, then you should set the dremio parameters in `dremio-module.yaml` as the following:
```
dremio.host: "dremio-client.fybrik-blueprints.svc.cluster.local"
dremio.port: "9047"
dremio.enabled: "true"
```
Then, apply the fybrik module using the following command:
```bash
kubectl apply -f dremio-module.yaml -n fybrik-system
```

### Create namespace
```bash
kubectl create namespace fybrik-notebook-sample
kubectl config set-context --current --namespace=fybrik-notebook-sample
```

### Register asset and secrets
```bash
kubectl apply -f sample_assets/asset-iceberg.yaml -n fybrik-notebook-sample
```
Replace the values for access_key and secret_key in `sample_asset/secret-iceberg.yaml` file with the values from the object storage service that you used and run:
```bash
kubectl apply -f sample_assets/secret-iceberg.yaml -n fybrik-notebook-sample
kubectl apply -f sample_assets/secret-dremio.yaml -n fybrik-notebook-sample
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

Wait For the pod `my-notebook-default-dremio-module-xxxx` to be completed. This pod runs a python code that registers the asset in dremio and applies the policy to create a virtual dataset. The user can use the following credentials to connect to Dremio:

    "name": "newUser", 
    "password": "testpassword123"
