# DremioModule

### Before you begin
Ensure that you have the following:

- Helm 3.3 or greater must be installed and configured on your machine.
- Kubectl 1.18 or newer must be installed on your machine.
- Access to a Kubernetes cluster such as Kind as a cluster administrator.

### Install fybrik
Install Fybrik v0.6 using the [Quick Start](https://fybrik.io/v0.6/get-started/quickstart/), without the section of `Install modules`.

### Register the fybrikmodule:
In `dremio-module.yaml` you can specify the host and port of an existing and running dremio cluster (and to set the `dremio.enabled` value to "false"). Another option is to tell fybrik to start a dremio cluster, then you should set the dremio parameters as the following:
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

### Create iceberg asset
To be done.

### Register iceberg asset
Replace the values of `endpoint`, `bucket`, and `object_key` in `sample_asset/asset-iceberg.yaml` file according to your created asset. Then, add the asset to the internal catalog using the following command:

```bash
kubectl apply -f sample_assets/asset-iceberg.yaml -n fybrik-notebook-sample
```
The asset has been marked as a `finance` data and the column `_c1` has been marked with `PII` tag.

### Register iceberg access secret
Replace the values for `access_key` and `secret_key` in `sample_asset/secret-iceberg.yaml` file with the values from the object storage service that you used and run:
```bash
kubectl apply -f sample_assets/secret-iceberg.yaml -n fybrik-notebook-sample
```

### Define data access policy
Register a policy. The example policy removes columns tagged as `PII` from datasets marked as `finance`.
```bash
kubectl -n fybrik-system create configmap sample-policy --from-file=sample_assets/sample-policy.rego
kubectl -n fybrik-system label configmap sample-policy openpolicyagent.org/policy=rego
while [[ $(kubectl get cm sample-policy -n fybrik-system -o 'jsonpath={.metadata.annotations.openpolicyagent\.org/policy-status}') != '{"status":"ok"}' ]]; do echo "waiting for policy to be applied" && sleep 5; done
```

### Deploy Fybrik application
```bash
kubectl apply -f fybrikapplication.yaml
```
Deployment of this `fybrikapplication` installs and runs a dremio server. We plan to support using an external dremio server as well.

Wait for the fybrik module (could take few minutes):
```bash
while [[ ($(kubectl get fybrikapplication my-notebook -o 'jsonpath={.status.ready}') != "true") || ($(kubectl get jobs my-notebook-fybrik-notebook-sample-dremio-module -n fybrik-blueprints -o 'jsonpath={.status.conditions[0].type}') != "Complete") ]]; do echo "waiting for FybrikApplication" && sleep 5; done
```
<<<<<<< HEAD
=======

Wait For the pod `my-notebook-default-dremio-module-xxxx` to be completed. This pod runs a python code that registers the asset in dremio and applies the policy to create a virtual dataset. The user can use the following credentials to connect to Dremio:
>>>>>>> Using subchart for dremio cluster.

Use port-forward to access Dremio
```
kubectl port-forward svc/dremio-client -n fybrik-blueprints 9047:9047 &
```
You can access Dremio via the browser on `http://localhost:9047/`, use the following credentials:
    "name": "newUser", 
    "password": "testpassword123"

You can enter into the `Space-api` space then select the `sample-iceberg-vds` virtual dataset that was created by the module accoring to the polices. You can see that the column `_c1` is missing because it was tagged as a `PII` data in the original dataset.


### Cleanup
1. Stop kubectl port-forward processes (e.g., using `pkill kubectl`)
1. Delete the `fybrik-notebook-sample` namespace:
    ```bash
    kubectl delete namespace fybrik-notebook-sample
    ```
1. Delete the policy created in the `fybrik-system` namespace:
    ```bash
    NS="fybrik-system"; kubectl -n $NS get configmap | awk '/sample/{print $1}' | xargs  kubectl delete -n $NS configmap
    ```
