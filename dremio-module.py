"""
  Copyright (C) 2017-2021 Dremio Corporation

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
"""

##############################################################
#
# Copyright 2020 IBM Corp.
# SPDX-License-Identifier: Apache-2.0
#

# from fybrik_python_logging import logger, Error, DataSetID, ForUser
import requests

def get_jwt_from_file(file_name):
    """
    Getting a jwt from a file.
    Typically, an SA token, which would be at: /var/run/secrets/kubernetes.io/serviceaccount/token
    """
    with open(file_name) as f:
        return f.read()

def vault_jwt_auth(jwt, vault_address, vault_path, role, datasetID):
    """Authenticate against Vault using a JWT token (i.e., k8s sa token)"""
    full_auth_path = vault_address + vault_path
    # logger.trace('authenticating against vault using a JWT token',
    #     extra={'full_auth_path': str(full_auth_path),
    #            DataSetID: datasetID})
    json = {"jwt": jwt, "role": role}
    response = requests.post(full_auth_path, json=json)
    if response.status_code == 200:
        return response.json()
    # logger.error("vault authentication failed",
    #     extra={Error: str(response.status_code) + ': ' + str(response.json()),
    #            DataSetID: datasetID, ForUser: True})
    return None

def get_raw_secret_from_vault(jwt, secret_path, vault_address, vault_path, role, datasetID):
    """Get a raw secret from vault by providing a valid jwt token"""
    vault_auth_response = vault_jwt_auth(jwt, vault_address, vault_path, role, datasetID)
    if vault_auth_response is None:
        # logger.error("Empty vault authorization response",
        #              extra={DataSetID: datasetID, ForUser: True})
        return None
    if not "auth" in vault_auth_response or not "client_token" in vault_auth_response["auth"]:
        # logger.error("Malformed vault authorization response",
        #              extra={DataSetID: datasetID, ForUser: True})
        return None
    client_token = vault_auth_response["auth"]["client_token"]
    secret_full_path = vault_address + secret_path
    response = requests.get(secret_full_path, headers={"X-Vault-Token" : client_token})
    # logger.debug('Response received from vault when accessing credentials: ' + str(response.status_code),
    #     extra={'credentials_path': str(secret_full_path),
    #            DataSetID: datasetID, ForUser: True})
    if response.status_code == 200:
        response_json = response.json()
        if 'data' in response_json:
            return response_json['data']
        # else:
            # logger.error("Malformed secret response. Expected the 'data' field in JSON",
            #              extra={DataSetID: datasetID, ForUser: True})
    # else:
        # logger.error("Error reading credentials from vault",
        #     extra={Error: str(response.status_code) + ': ' + str(response.json()),
        #            DataSetID: datasetID, ForUser: True})
    return None

def get_credentials_from_vault(vault_credentials, datasetID):
    jwt_file_path = vault_credentials.get('jwt_file_path', '/var/run/secrets/kubernetes.io/serviceaccount/token')
    jwt = get_jwt_from_file(jwt_file_path)
    vault_address = vault_credentials.get('address', 'https://localhost:8200')
    secret_path = vault_credentials.get('secretPath', '/v1/secret/data/cred')
    vault_auth = vault_credentials.get('authPath', '/v1/auth/kubernetes/login')
    role = vault_credentials.get('role', 'demo')
    # logger.trace('getting vault credentials',
    #     extra={'jwt_file_path': str(jwt_file_path),
    #            'vault_address': str(vault_address),
    #            'secret_path': str(secret_path),
    #            'vault_auth': str(vault_auth),
    #            'role': str(role),
    #            DataSetID: datasetID,
    #            ForUser: True})
    credentials = get_raw_secret_from_vault(jwt, secret_path, vault_address, vault_auth, role, datasetID)
    if not credentials:
        raise ValueError("Vault credentials are missing")
    if 'access_key' in credentials and 'secret_key' in credentials:
        if credentials['access_key'] and credentials['secret_key']:
            return credentials['access_key'], credentials['secret_key']
        # else:
        #     if not credentials['access_key']:
        #         # logger.error("'access_key' must be non-empty",
        #         #              extra={DataSetID: datasetID, ForUser: True})
        #     if not credentials['secret_key']:
        #         # logger.error("'secret_key' must be non-empty",
        #         #              extra={DataSetID: datasetID, ForUser: True})
    # logger.error("Expected both 'access_key' and 'secret_key' fields in vault secret",
    #              extra={DataSetID: datasetID, ForUser: True})
    raise ValueError("Vault credentials are missing")

##############################################################




import argparse
import base64
import json
import logging
from time import sleep
import certifi
import sys
import yaml
import requests
import pandas as pd
# from .vault import get_credentials_from_vault


from http.cookies import SimpleCookie
from pyarrow import flight

data_dict = {}



def parse_arguments():
    """
    Parses the command-line arguments supplied to the script.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-host', '--hostname', type=str,
                        help='Dremio co-ordinator hostname. Defaults to \"localhost\".',
                        default='localhost')
    parser.add_argument('-port', '--flightport', dest='port', type=int,
                        help='Dremio flight server port. Defaults to 32010.',
                        default=32010)
    parser.add_argument('-user', '--username', type=str, help='Dremio username. Defaults to \"dremio\".',
                        default="dremio")
    parser.add_argument('-pass', '--password', type=str, help='Dremio password. Defaults to \"dremio123\".',
                        default="dremio123")
    parser.add_argument('-pat', '--personalAccessToken', '-authToken', '--authToken', dest='pat_or_auth_token', type=str,
                        help="Either a Personal Access Token or an OAuth2 Token.",
                        required=False)
    parser.add_argument('-query', '--sqlQuery', dest="query", type=str,
                        help='SQL query to test',
                        required=True)
    parser.add_argument('-tls', '--tls', dest='tls', help='Enable encrypted connection. Defaults to False.',
                        default=False, action='store_true')
    parser.add_argument('-dsv', '--disableServerVerification', dest='disable_server_verification', type=bool,
                        help='Disable TLS server verification. Defaults to False.',
                        default=False)
    parser.add_argument('-certs', '--trustedCertificates', dest='trusted_certificates', type=str,
                        help='Path to trusted certificates for encrypted connection. Defaults to system certificates.',
                        default=certifi.where())
    parser.add_argument('-sp', '--sessionProperty', dest='session_properties',
                        help="Key value pairs of SessionProperty, example: -sp schema=\'Samples.\"samples.dremio.com\"' -sp key=value",
                        required=False, nargs='*', action=KVParser)
    parser.add_argument('-engine', '--engine', type=str, help='The specific engine to run against.',
                        required=False)

    return parser.parse_args()


def fetch_cols_from_query(query):
    start = -1
    end = -1
    words = query.split()
    for i, w in enumerate(words):
        if w == 'SELECT':
            start = i + 1
        elif w == 'FROM':
            end = i - 1
    cols = words[start:end+1]
    for i, c in enumerate(cols):
        if c[-1] == ',':
            cols[i] = c[:len(c) - 1]
    return cols


#################################################################################################
def get_policies_from_conf():
    with open("/etc/conf/conf.yaml", 'r') as stream:
        content = yaml.safe_load(stream)
        #logging.info(content)
        for key,val in content.items():
            if "data" in key:
                for i in range(len(val)):
                    data = val[i]
                    connectionName = data["name"]
                    name = connectionName.split("/")[1]
                    format = data["format"]
                    endpoint_url = data["connection"]["s3"]["endpoint_url"]
                    vault_credentials = data["connection"]["s3"]["vault_credentials"]
                    transformations = base64.b64decode(data["transformations"])
                    data_dict[name] = {'format':format, 'endpoint_url':endpoint_url, 'transformations':transformations}
    # print("The available datasets:\n")
    # for key in data_dict:
    #     print("dataset name: {}\n".format(key))
    #     for k in data_dict[key]:
    #         print("    {}: {}\n".format(k, data_dict[key][k]))

    # print("gg columns {}\n".format(data_dict["bank"]["transformations"].decode("utf-8")))
    transformations_bytes = data_dict["bank"]["transformations"]
    transformations_json = json.loads(transformations_bytes.decode('utf-8'))
    transformation_cols = transformations_json[0]["RemoveAction"]["columns"]
    transformation = "RemoveCols"

    # Get credintials
    print("vault credentials = {}\n".format(vault_credentials))
    creds = get_credentials_from_vault(vault_credentials, "fybrik-notebook-sample/bank")
    print(creds)
    # get_raw_secret_from_vault(jwt, secret_path, vault_address, vault_auth, role, datasetID)

    return (transformation, transformation_cols, creds, endpoint_url)


def api_get(server, endpoint=None, headers=None, body=None):
    print(endpoint)
    return json.loads(requests.get(url='{server}/api/v3/{endpoint}'.format(server=server, endpoint=endpoint), headers=headers, data=json.dumps(body)).text)


def api_post(server, endpoint=None, body=None, headers=None):
    text = requests.request("POST", '{server}/api/v3/{endpoint}'.format(server=server, endpoint=endpoint), headers=headers, data=json.dumps(body)).text

    # a post may return no data
    if (text):
        return json.loads(text)
    else:
        return None


def api_put(server, endpoint=None, body=None, headers=None):
    return requests.put('{server}/api/v3/{endpoint}'.format(server=server, endpoint=endpoint), headers=headers, data=json.dumps(body)).text


def api_delete(server, endpoint=None, headers=None):
    return requests.delete('{server}/api/v3/{endpoint}'.format(server=server, endpoint=endpoint), headers=headers)


def login(server, username, password, headers=None):
    # we login using the old api for now
    loginData = {'userName': username, 'password': password}
    response = requests.post('{server}/apiv2/login'.format(server=server), headers=headers, data=json.dumps(loginData))
    print(response)
    data = json.loads(response.text)

    # retrieve the login token
    token = data['token']
    return {'Content-Type': 'application/json', 'Authorization': '_dremio{authToken}'.format(authToken=token)}





if __name__ == "__main__":

    username = "mohammadtn1"
    password = "Mtn#2061891"
    json_headers = {'content-type': 'application/json'}
    # dremioServer = 'http://localhost:9047'
    dremioServer = 'http://dremio-client.fybrik-blueprints.svc.cluster.local:9047'

    # Create a user
    # curl 'http://localhost:9047/apiv2/bootstrap/firstuser' -X PUT \
    #   -H 'Authorization: _dremionull' -H 'Content-Type: application/json' \
    #  --data-binary '{"userName":"banana","firstName":"banana","lastName":"banana","email":"banana@banana.com","createdAt":1526186430755,"password":"bananas4ever"}'
    data_user = {
        "userName": "adminUser",
        "firstName": "user",
        "lastName": "admin",
        "email": "test@test.com",
        "createdAt": 1526186430755,
        "password": "adminPwd",
    }
    headers = {'Content-Type': 'application/json', 'Authorization': '_dremionull'}
    # response = api_post(dremioServer, "user", data_user, headers)
    response = requests.request("PUT", 'http://dremio-client.fybrik-blueprints.svc.cluster.local:9047/apiv2/bootstrap/firstuser', data=json.dumps(data_user), headers=headers)
    print("register user")
    print(response.text)

    auth_headers = login(dremioServer, username, password, json_headers)
    print("headers")
    print(auth_headers)


    # Get the dataset details from configuration
    transformation, transformation_cols, creds, endpoint = get_policies_from_conf()
    print("conf parse")
    print(transformation)
    print(transformation_cols)
    print(creds[0])
    print(endpoint)

    # Create a new source from an s3 bucket
    source_name = "testingS3"
    data_s3 = {
        "entityType": "source",
        "name": source_name,
        "type": "S3",
        "config": {
            "accessKey": creds[0],
            "accessSecret": creds[1],
            "secure": "false",
            "allowCreateDrop": "true",
            "rootPath": "/",
            "credentialType": "ACCESS_KEY",
            "enableAsync": "true",
            "compatibilityMode": "true",
            "isCachingEnabled": "true",
            "maxCacheSpacePct": 100,
            "requesterPays": "false",
            "enableFileStatusCheck": "true",
            "propertyList": [
                {"name": "fs.s3a.path.style.access", "value": "true"},
                {"name": "fs.s3a.endpoint", "value": endpoint},
            ],
        },
    }

    response = api_post(dremioServer, "catalog", data_s3, auth_headers)
    print("new source")
    print(response)

    # Get data folder path
    print("gg")
    response = api_get(dremioServer, endpoint="catalog/by-path/{}/fybric-objectstorage-iceberg-demo/warehouse/db/table".format(source_name), headers=auth_headers)
    print("get path")
    print(response)

    # Promote a folder to dataset
    dataPromote = {
        "entityType": "dataset",
        "id": "dremio:/" + source_name + "/fybric-objectstorage-iceberg-demo/warehouse/db/table",
        "path": [
    	    source_name,
            "fybric-objectstorage-iceberg-demo",
    	    "warehouse",
    	    "db",
    	    "table"
    	],
    	
        "type": "PHYSICAL_DATASET",
        "format": {
            "type": "Iceberg"
        }
    }
    response = api_post(dremioServer, "catalog/dremio%3A%2F" + source_name + "%2Ffybric-objectstorage-iceberg-demo%2Fwarehouse%2Fdb%2Ftable", dataPromote, auth_headers)
    print("promote")
    print(response)


    # Get the columns of the new source
    print("dataSQL")
    dataSQL = {
        "sql": 'SELECT * FROM "' + source_name + '"."fybric-objectstorage-iceberg-demo"."warehouse"."db"."table" LIMIT 0'
    }
    response = api_post(dremioServer, "sql", dataSQL, auth_headers)
    print(response.get("id"))
    job_id = response.get("id")
    
    response = api_get(dremioServer, "job/"+job_id, auth_headers, dataSQL)
    print(response.get("jobState"))
    while(response.get("jobState") != "COMPLETED"):
        print("wait for job")
        response = api_get(dremioServer, "job/"+job_id, auth_headers, dataSQL)
        print(response)
        sleep(10)
    response = api_get(dremioServer, "job/"+job_id+"/results", auth_headers, dataSQL)
    print(response.get("schema"))
    col_names = [elem.get("name") for elem in response.get("schema")]
    print(col_names)



    

    # Get the sql query from the policies
    request_cols = [col for col in col_names if col not in transformation_cols]
    print("requested_cols")
    print(request_cols)
    if len(request_cols) < 1:
        print("empty dataset")
    requested_cols_string = request_cols[0]
    for col in request_cols[1:]:
        add_col = ", " + col
        requested_cols_string += add_col
    sql_vds = "select " + requested_cols_string + ' from "table"'
    print("sql_vds")
    print(sql_vds)


    payloadSpace = {
        "entityType": "space",
        "name": "Space-api"
    }
    response = api_post(dremioServer, "catalog", payloadSpace, auth_headers)
    print(response)
    
    # Create a virtual dataset that represents the source dataset after applying the policies
    
    # payloadVDS = "{\n  \"entityType\": \"dataset\",\n  \"path\": [\n    \"@mohammadtn\",\n\"test-iceberg-api1\" \n  ],\n\t\"type\": \"VIRTUAL_DATASET\",\n\t\"sql\": \"select * from \"table\" \",\n\t\"sqlContext\": [\"testingS3\", \"fybric-objectstorage-iceberg-demo\", \"warehouse\", \"db\"]\n}"
    newVDSName = "test-iceberg-api4"
    dataVDS = {
        "entityType": "dataset",
        "path": [
            "Space-api",
            newVDSName,
        ],
	    "type": "VIRTUAL_DATASET",
	    "sql": sql_vds,
	    "sqlContext": [source_name, "fybric-objectstorage-iceberg-demo", "warehouse", "db"]
    }
    
    # headers = {
    #     'Authorization': "_dremiogavgbr3fnpm425qt5rikobgqj8",
    #     'Content-Type': "application/json"
    # }
    # response = requests.request("POST", url, data=json.dumps(dataVDS), headers=headers)
    response = api_post(dremioServer, "catalog", dataVDS, auth_headers)
    print("VDS")
    print(response)

    # Add a new user
    dataNewUser = {
        "name": "newUser",
        "firstName": "first",
        "password": "testpassword123",
    }
    response = api_post(dremioServer, "user", dataNewUser, auth_headers)
    print("new user")
    print(response)

   
############################################
# curl -X POST --location "http://localhost:9047/api/v3/user" \
#     -H "Authorization:_dremiorah9dul2ncrol0khug88qchbhu" \
#     -H "Content-Type: application/json" \
#     -H "Accept: application/json" \
#     -d "{\"name\":  \"test_user2\", \"firstName\": \"first1\", \"password\": \"testpassword123\", \"id\":  \"d4f430eb-af38-4514-8fed-226d1ddbea6a\"}"

# curl -X GET --location "http://localhost:9047/api/v3/test_user2/d4f430eb-af38-4514-8fed-226d1ddbea6a/privileges" \
#     -H "Authorization: _dremiorah9dul2ncrol0khug88qchbhu" \
#     -H "Content-Type: application/json" \
#     -H "Accept: application/json"

#     curl -X GET --location "http://localhost:9047/api/v3/grant?grantType=SPACE" \
#     -H "Authorization: _dremiorah9dul2ncrol0khug88qchbhu" \
#     -H "Content-Type: application/json" \
#     -H "Accept: application/json"