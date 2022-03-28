# Sample

This example helps in trying the read module locally without kubernetes.
The file `conf_sample.yaml` is an example of a `conf.yaml` file after configuring it by the Fybrik manager.
The python code `hello-world-module` reads the values of `conf_sample.yaml` and launches a simple web server to respond to GET requests of datasets registered in `conf_sample.yaml`.
The file `test_client_sample.py` is an example of a client who requests the data.

## Steps

1. Run the server with
    ```bash
    python3 ../hello-world-module.py --config conf_sample.yaml
    ```
1. Run a sample client with
    ```bash
    python3 sample.py --data <assetID>
    ```
