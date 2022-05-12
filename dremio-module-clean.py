import json
import socket
from time import sleep
import yaml
import requests
from fybrik_python_logging import logger

data_dict = {}

def get_details_from_conf():
    """ Parse the configuration and get the data details and policies """
    with open("/etc/conf/conf.yaml", 'r') as stream:
    # with open("sample-conf.yaml", 'r') as stream:
        content = yaml.safe_load(stream)
        if "dremioHost" in content.keys():
            dremio_host = content["dremioHost"]
        if "dremioPort" in content.keys():
            dremio_port = content["dremioPort"]
        for key, val in content.items():
            if "data" in key:
                for data in val:
                    dataset_id = data["name"]
                    name = dataset_id.split("/")[1]
                    data_dict[name] = {'path': data["path"]}

    return data_dict[name], dremio_host, dremio_port


def api_get(server, endpoint=None, headers=None, body=None):
    """" Run GET command """
    print('{server}/api/v3/{endpoint}'.format(server=server, endpoint=endpoint))
    return json.loads(requests.get(url='{server}/api/v3/{endpoint}'.format(server=server, endpoint=endpoint), headers=headers, data=json.dumps(body)).text)


def api_post(server, endpoint=None, body=None, headers=None):
    """" Run POST command """
    text = requests.request("POST", '{server}/api/v3/{endpoint}'.format(server=server, endpoint=endpoint), headers=headers, data=json.dumps(body)).text

    # a post may return no data
    if (text):
        return json.loads(text)
    else:
        return None

def api_put(server, endpoint=None, body=None, headers=None):
    """" Run PUT command """
    return requests.put('{server}/api/v3/{endpoint}'.format(server=server, endpoint=endpoint), headers=headers, data=json.dumps(body)).text


def api_delete(server, endpoint=None, headers=None):
    """" Run DELETE command """
    return requests.delete('{server}/api/v3/{endpoint}'.format(server=server, endpoint=endpoint), headers=headers)


def login(server, username, password, headers=None):
    """" Login to Dremio using the given username and password """
    login_data = {'userName': username, 'password': password}
    response = requests.post('{server}/apiv2/login'.format(server=server), headers=headers, data=json.dumps(login_data))
    logger.debug("Login response: %s", response)
    data = json.loads(response.text)

    # retrieve the login token
    token = data['token']
    return {'Content-Type': 'application/json', 'Authorization': '_dremio{authToken}'.format(authToken=token)}


def wait_dremio(dremio_host, dremio_port):
    """ Try to connect to Dremio until success or timeout """
    a_socket = socket.socket()
    count = 0
    while count < 30:
        logger.debug("wait dremio")
        print(dremio_host)
        try:
            a_socket.connect((dremio_host, dremio_port))
        except:
            sleep(10)
            count += 1
            continue
        break

def get_resource_id(dremio_server, path, auth_headers):
    response = api_get(dremio_server, "catalog/by-path/" + path, auth_headers, "")
    print(response)
    if 'id' in response:
        return response['id']

def delete_resource(dremio_server, id, auth_headers):
    response = api_delete(dremio_server, "catalog/" + id, auth_headers)
    # Check response

if __name__ == "__main__":
    # TODO: find a way to get the admin user and password
    username = "adminUser"
    password = "adminPwd1"
    json_headers = {'content-type': 'application/json'}
    # dremio_server = 'http://localhost:9047'
    # TODO: find a way to get the namespace where the dremio is running (maybe also the service name)
    # dremio_namespace = 'fybrik-notebook-sample'
    # dremio_port = 9047
    # dremio_server = 'http://dremio-client.' + dremio_namespace + '.svc.cluster.local:9047'
    # dremio_host = 'dremio-client.' + dremio_namespace + '.svc.cluster.local'

    # Get the dataset details from configuration
    parse_conf, dremio_host, dremio_port = get_details_from_conf()
    dremio_server = "http://" + dremio_host + ":" + str(dremio_port)

    # Wait for dremio to be ready
    wait_dremio(dremio_host, dremio_port)
    # Login to Dremio with admin user
    auth_headers = login(dremio_server, username, password, json_headers)
    
    
    # Delete the user

    # Remove the VDS
    vds_path = "Space-api/sample-iceberg-vds"
    vds_id = get_resource_id(dremio_server, vds_path, auth_headers)
    if vds_id:
        delete_resource(dremio_server, vds_id, auth_headers)

    # Remove the space
    space_path = "Space-api"
    space_id = get_resource_id(dremio_server, space_path, auth_headers)
    if space_id:
        delete_resource(dremio_server, space_id, auth_headers)

    # Remove the source
    source_path = "sample-iceberg"
    source_id = get_resource_id(dremio_server, source_path, auth_headers)
    if source_id:
        delete_resource(dremio_server, source_id, auth_headers)
