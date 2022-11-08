# Dremio Module

This module configures a Dremio cluster for data access in Fybrik. The module can either deploy a new Dremio cluster or use an existing one.

### Before you begin
Ensure that you have the following:

- Helm 3.3 or greater must be installed and configured on your machine.
- Kubectl 1.18 or newer must be installed on your machine.
- Access to a Kubernetes cluster such as Kind as a cluster administrator.

### Install fybrik
Install Fybrik v1.1 using the [Quick Start](https://fybrik.io/v1.1/get-started/quickstart/), without the section of `Install modules`.

### Install Dremio (Optional)
You can install a Dremio cluster using the following command:
```bash
helm install <chart-name> charts/dremio-module/charts/dremio-cluster
```

### Register the Fybrik module:
In `dremio-module.yaml` can you specify the host and port of an already existing Dremio cluster. If Dremio is deployed using the previous step, you can set the dremio parameters in `dremio-module.yaml` as the following:
```
dremio.host: "dremio-client.<namespace of the dremio chart>.svc.cluster.local"
dremio.port: "9047"
```

Alternatively, you can ask fybrik to deploy a new dremio cluster. To that end, set the dremio parameters in `dremio-module.yaml` as the following:
```
dremio.host: "dremio-client.fybrik-blueprints.svc.cluster.local"
dremio.port: "9047"
dremio.enabled: "true"
```

Either way, apply the fybrik module using the following command:
```bash
kubectl apply -f dremio-module.yaml -n fybrik-system
```

### Create iceberg asset
TBD

### Create namespace
```bash
kubectl create namespace fybrik-sample
kubectl config set-context --current --namespace=fybrik-sample
```

### Register Iceberg asset
Replace the values of `endpoint`, `bucket`, and `object_key` in `sample/asset-iceberg.yaml` file according to your created asset. Then, add the asset to the internal catalog using the following command:

```bash
kubectl apply -f sample/asset-iceberg.yaml
```
The asset has been marked as a `finance` data and the column `_c1` has been marked with `PII` tag.

### Register iceberg access secret
First, create a K8S secret for the credentials for accessing the iceberg table. Assuming the credentials are stored in as the environment variables `ACCESS_KEY` and `SECRET_KEY` respectivley, this can be done by:
```bash
kubectl create secret generic iceberg-dataset --from-literal=access_key=${ACCESS_KEY} --from-literal=secret_key=${SECRET_KEY}
```

You should also create a secret for accessing the dremio cluster:
```bash
kubectl apply -f sample/secret-dremio.yaml
```

### Define data access policy
Register a policy. The example policy removes columns tagged as `PII` from datasets marked as `finance`.
```bash
kubectl -n fybrik-system create configmap sample-policy --from-file=sample/sample-policy.rego
kubectl -n fybrik-system label configmap sample-policy openpolicyagent.org/policy=rego
while [[ $(kubectl get cm sample-policy -n fybrik-system -o 'jsonpath={.metadata.annotations.openpolicyagent\.org/policy-status}') != '{"status":"ok"}' ]]; do echo "waiting for policy to be applied" && sleep 5; done
```

### Deploy Fybrik application
The following `fybrikapplication` deploys a dremio cluster (if specificed so by the dremio-module) and configures it via a k8s job, which registers the Iceberg asset in dremio and applies the policy to create a virtual dataset.

```bash
kubectl apply -f sample/fybrikapplication.yaml
```

Wait for the `fybrikapplication` to be ready (could take a few minutes):
```bash
while [[ ($(kubectl get fybrikapplication fybrik-iceberg-sample -o 'jsonpath={.status.ready}') != "true") || ($(kubectl get jobs fybrik-iceberg-sample-fybrik-sample-dremio-module -n fybrik-blueprints -o 'jsonpath={.status.conditions[0].type}') != "Complete") ]]; do echo "waiting for FybrikApplication" && sleep 5; done
```

Use port-forward to access Dremio
```bash
kubectl port-forward svc/dremio-client -n <ns-of-dremio> 9047:9047 &
```

You can access Dremio via the browser on `http://localhost:9047/`, use the following credentials:
    "name": "newUser", 
    "password": "testpassword123"

You can enter into the `Space-api` space then select the `sample-iceberg-vds` virtual dataset that was created by the module accoring to the polices.

You can also query the data set using the `sample/query_sample.py`, for instance:
```bash
python sample/query.py --query '{"sql": "SELECT _c0 FROM \"Space-api\".\"sample-iceberg-vds\""}'
```


### Cleanup
1. Stop kubectl port-forward processes (e.g., using `pkill kubectl`)
1. Delete the `fybrikapplication`:
    ```bash
    kubectl delete -f sample_assets/fybrikapplication.yaml
    ```
1. Delete the `fybrik-sample` namespace:
    ```bash
    kubectl delete namespace fybrik-sample
    ```
1. Delete the policy created in the `fybrik-system` namespace:
    ```bash
    NS="fybrik-system"; kubectl -n $NS get configmap | awk '/sample/{print $1}' | xargs  kubectl delete -n $NS configmap
    ```
