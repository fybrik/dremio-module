import base64
import json
import socket
from time import sleep
import yaml
import requests
from fybrik_python_vault import get_jwt_from_file, get_raw_secret_from_vault
from fybrik_python_logging import init_logger, logger, DataSetID, ForUser
 

data_dict = {}


def get_credentials_from_vault(vault_credentials, secret_path, data_set_id):
    """ Use the fybrik-python-library to get the access_key and secret_key from vault for s3 dataset """
    jwt_file_path = vault_credentials.get('jwt_file_path', '/var/run/secrets/kubernetes.io/serviceaccount/token')
    jwt = get_jwt_from_file(jwt_file_path)
    vault_address = vault_credentials.get('address', 'https://localhost:8200')
    vault_auth = vault_credentials.get('authPath', '/v1/auth/kubernetes/login')
    role = vault_credentials.get('role', 'demo')
    credentials = get_raw_secret_from_vault(jwt, secret_path, vault_address, vault_auth, role, data_set_id)
    if not credentials:
        raise ValueError("Vault credentials are missing")
    if 'access_key' in credentials and 'secret_key' in credentials:
        if credentials['access_key'] and credentials['secret_key']:
            return credentials['access_key'], credentials['secret_key']
        if not credentials['access_key']:
            logger.error("'access_key' must be non-empty",
                            extra={DataSetID: data_set_id, ForUser: True})
        if not credentials['secret_key']:
            logger.error("'secret_key' must be non-empty",
                            extra={DataSetID: data_set_id, ForUser: True})
    logger.error("Expected both 'access_key' and 'secret_key' fields in vault secret",
                 extra={DataSetID: data_set_id, ForUser: True})
    raise ValueError("Vault credentials are missing")


def get_details_from_conf():
    """ Parse the configuration and get the data details and policies """
    with open("/etc/conf/conf.yaml", 'r') as stream:
        content = yaml.safe_load(stream)
        if "dremioHost" in content.keys():
            dremio_host = content["dremioHost"]
        if "dremioPort" in content.keys():
            dremio_port = content["dremioPort"]
        if "dremioCredNS" in content.keys():
            dremio_cred_ns = content["dremioCredNS"]
        for key, val in content.items():
            if "data" in key:
                for data in val:
                    dataset_id = data["name"]
                    name = dataset_id.split("/")[1]
                    endpoint_url = data["connection"]["s3"]["endpoint_url"]
                    vault_credentials = data["connection"]["s3"]["vault_credentials"]
                    asset_creds = get_credentials_from_vault(vault_credentials, vault_credentials.get('secretPath', '/v1/secret/data/cred'), dataset_id)
                    secret_path = "/v1/kubernetes-secrets/dremio-cluster?namespace=" + dremio_cred_ns
                    dremio_creds = get_credentials_from_vault(vault_credentials, secret_path, dataset_id)
                    logger.debug("creds: " + asset_creds[0] + "   " + asset_creds[1] + "   " + dremio_creds[0] + "   " + dremio_creds[1])
                    transformations = base64.b64decode(data["transformations"])
                    transformations_json = json.loads(transformations.decode('utf-8'))
                    transformation = transformations_json[0]['name']
                    transformation_cols = transformations_json[0][transformation]["columns"]
                    data_dict[name] = {'format': data["format"], 'endpoint_url': endpoint_url, 'path': data["path"], 'transformation': transformation,
                     'transformation_cols': transformation_cols, 'asset_creds': asset_creds, 'dremio_creds': dremio_creds}
    return data_dict[name], dremio_host, dremio_port


def api_get(server, endpoint=None, headers=None, body=None):
    """" Run GET command """
    return json.loads(requests.get(url='{server}/api/v3/{endpoint}'.format(server=server, endpoint=endpoint), headers=headers, data=json.dumps(body)).text)


def api_post(server, endpoint=None, headers=None, body=None):
    """" Run POST command """
    text = requests.request("POST", '{server}/api/v3/{endpoint}'.format(server=server, endpoint=endpoint), headers=headers, data=json.dumps(body)).text

    # a post may return no data
    if (text):
        return json.loads(text)
    else:
        return None


def api_delete(server, endpoint=None, headers=None):
    """" Run DELETE command """
    return requests.delete('{server}/api/v3/{endpoint}'.format(server=server, endpoint=endpoint), headers=headers)


def login(server, username, password, headers=None):
    """" Login to Dremio using the given username and password """
    loginData = {'userName': username, 'password': password}
    response = requests.post('{server}/apiv2/login'.format(server=server), headers=headers, data=json.dumps(loginData))
    logger.debug("Login response: %s", response)
    data = json.loads(response.text)

    # retrieve the login token
    token = data['token']
    return {'Content-Type': 'application/json', 'Authorization': '_dremio{authToken}'.format(authToken=token)}


def wait_dremio(dremio_host, dremio_port, timeout=600):
    """ Try to connect to Dremio until success or timeout """
    a_socket = socket.socket()
    slept = 0
    while slept < timeout:
        logger.info("Wait dremio")
        try:
            logger.info("Trying to connect to dremio cluster at: %s:%s", dremio_host, dremio_port)
            a_socket.connect((dremio_host, dremio_port))
            return 0
        except:
            sleep(10)
            slept += 10
    # We must have timed out
    return 1


def wait_for_query(server, auth_headers, job_id, timeout=60):
    """ Wait for the query to finish """
    result_endpoint = "job/{id}".format(id=job_id)
    slept = 0
    while slept < timeout:
        logger.info("Wait for query")
        results = api_get(server, endpoint=result_endpoint, headers=auth_headers)
        if results["jobState"] == "COMPLETED":
            return 0
        slept += 1
        sleep(1)
    # Timed out or job wasn't completed successfully
    return 1