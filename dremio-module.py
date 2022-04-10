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
import argparse
import base64
import json
import logging
import certifi
import sys
import yaml
import requests
import pandas as pd


from http.cookies import SimpleCookie
from pyarrow import flight

data_dict = {}

class DremioClientAuthMiddlewareFactory(flight.ClientMiddlewareFactory):
    """A factory that creates DremioClientAuthMiddleware(s)."""

    def __init__(self):
        self.call_credential = []

    def start_call(self, info):
        return DremioClientAuthMiddleware(self)

    def set_call_credential(self, call_credential):
        self.call_credential = call_credential


class DremioClientAuthMiddleware(flight.ClientMiddleware):
    """
    A ClientMiddleware that extracts the bearer token from 
    the authorization header returned by the Dremio 
    Flight Server Endpoint.

    Parameters
    ----------
    factory : ClientHeaderAuthMiddlewareFactory
        The factory to set call credentials if an
        authorization header with bearer token is
        returned by the Dremio server.
    """

    def __init__(self, factory):
        self.factory = factory

    def received_headers(self, headers):
        auth_header_key = 'authorization'
        authorization_header = []
        for key in headers:
            if key.lower() == auth_header_key:
                authorization_header = headers.get(auth_header_key)
        if not authorization_header:
            raise Exception('Did not receive authorization header back from server.')
        self.factory.set_call_credential([
            b'authorization', authorization_header[0].encode('utf-8')])


class CookieMiddlewareFactory(flight.ClientMiddlewareFactory):
    """A factory that creates CookieMiddleware(s)."""

    def __init__(self):
        self.cookies = {}

    def start_call(self, info):
        return CookieMiddleware(self)


class CookieMiddleware(flight.ClientMiddleware):
    """
    A ClientMiddleware that receives and retransmits cookies.
    For simplicity, this does not auto-expire cookies.

    Parameters
    ----------
    factory : CookieMiddlewareFactory
        The factory containing the currently cached cookies.
    """

    def __init__(self, factory):
        self.factory = factory

    def received_headers(self, headers):
        for key in headers:
            if key.lower() == 'set-cookie':
                cookie = SimpleCookie()
                for item in headers.get(key):
                    cookie.load(item)

                self.factory.cookies.update(cookie.items())

    def sending_headers(self):
        if self.factory.cookies:
            cookie_string = '; '.join("{!s}={!s}".format(key, val.value) for (key, val) in self.factory.cookies.items())
            return {b'cookie': cookie_string.encode('utf-8')}
        return {}


class KVParser(argparse.Action):
    def __call__(self, parser, namespace,
                 values, option_string=None):
        setattr(namespace, self.dest, list())
          
        for value in values:
            # split it into key and value
            key, value = value.split('=')
            # insert into list as key-value tuples
            getattr(namespace, self.dest).append((key.encode('utf-8'), value.encode('utf-8')))


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

def connect_to_dremio_flight_server_endpoint(host, port, username, password, query,
                                             tls, certs, disable_server_verification, pat_or_auth_token,
                                             engine, session_properties):
    """
    Connects to Dremio Flight server endpoint with the provided credentials.
    It also runs the query and retrieves the result set.
    """
    with open("sample-conf.yaml", 'r') as stream:
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
                    transformations = base64.b64decode(data["transformations"])
                    data_dict[name] = {'format':format, 'endpoint_url':endpoint_url, 'transformations':transformations}
    print("The available datasets:\n")
    for key in data_dict:
        print("dataset name: {}\n".format(key))
        for k in data_dict[key]:
            print("    {}: {}\n".format(k, data_dict[key][k]))

    print("gg columns {}\n".format(data_dict["bank"]["transformations"].decode("utf-8")))
    transformations_bytes = data_dict["bank"]["transformations"]
    transformations_json = json.loads(transformations_bytes.decode('utf-8'))
    Remove_cols = transformations_json[0]["RedactAction"]["columns"]
    Remove_cols.append('Category')
    print(Remove_cols)

    try:
        # Default to use an unencrypted TCP connection.
        scheme = "grpc+tcp"
        connection_args = {}


        headers = session_properties
        if not headers:
            headers = []

        # Two WLM settings can be provided upon initial authentication with the Dremio Server Flight Endpoint:
        # routing_tag
        # routing_queue
        headers.append((b'routing_tag', b'test-routing-tag'))
        headers.append((b'routing_queue', b'Low Cost User Queries'))

        client_cookie_middleware = CookieMiddlewareFactory()

        if username and password:
            client_auth_middleware = DremioClientAuthMiddlewareFactory()
            client = flight.FlightClient("{}://{}:{}".format(scheme, host, port),
                                         middleware=[client_auth_middleware, client_cookie_middleware],
                                         **connection_args)

            # Authenticate with the server endpoint.
            bearer_token = client.authenticate_basic_token(username, password,
                                                           flight.FlightCallOptions(headers=headers))
            print('[INFO] Authentication was successful')
            headers.append(bearer_token)
        else:
            print('[ERROR] Username/password or PAT/Auth token must be supplied.')
            sys.exit()

        if query:
            # Construct FlightDescriptor for the query result set.
            flight_desc = flight.FlightDescriptor.for_command(query)
            print('[INFO] Query: ', query)
            requested_cols = fetch_cols_from_query(query)
            print('[INFO] Requested Cols: ', requested_cols)
            for c in Remove_cols:
                if c in requested_cols:
                    requested_cols.remove(c)

            print('[INFO] Requested Cols: ', requested_cols)

            # In addition to the bearer token, a query context can also
            # be provided as an entry of FlightCallOptions.
            # options = flight.FlightCallOptions(headers=[
            #     bearer_token,
            #     (b'schema', b'test.schema')
            # ])

            # Retrieve the schema of the result set.
            options = flight.FlightCallOptions(headers=headers)
            schema = client.get_schema(flight_desc, options)
            print('[INFO] GetSchema was successful')
            print('[INFO] Schema: ', schema)

            # Get the FlightInfo message to retrieve the Ticket corresponding
            # to the query result set.
            flight_info = client.get_flight_info(flight.FlightDescriptor.for_command(query), options)
            print('[INFO] GetFlightInfo was successful')
            print('[INFO] Ticket: ', flight_info.endpoints[0].ticket)

            # Retrieve the result set as a stream of Arrow record batches.
            reader = client.do_get(flight_info.endpoints[0].ticket, options)
            print('[INFO] Reading query results from Dremio')
            print(reader.read_pandas())

    except Exception as exception:
        print("[ERROR] Exception: {}".format(repr(exception)))
        raise




import json
import requests




def api_get(server, endpoint=None, headers=None):
    return json.loads(requests.get('{server}/api/v3/{endpoint}'.format(server=server, endpoint=endpoint), headers=headers).text)


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

    url = "http://localhost:9047/api/v3/catalog"

    username = "XXXX"
    password = "XXXX"
    json_headers = {'content-type': 'application/json'}
    dremioServer = 'http://localhost:9047'
    auth_headers = login(dremioServer, username, password, json_headers)

    # Create a new source from an s3 bucket
    data_s3 = {
        "entityType": "source",
        "name": "testingS3",
        "type": "S3",
        "config": {
            "accessKey": "XXXX",
            "accessSecret": "XXXX",
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
                {"name": "fs.s3a.endpoint", "value": "s3.eu-de.cloud-object-storage.appdomain.cloud"},
            ],
        },
    }

    response = api_post(dremioServer, "catalog", data_s3, auth_headers)
    print(response)


    # Create a virtual dataset that represents the source dataset after applying the policies

    # payloadSpace = "{\n    \"entityType\": \"space\",\n    \"name\": \"Space-api\"\n}"
    # payloadVDS = "{\n  \"entityType\": \"dataset\",\n  \"path\": [\n    \"@mohammadtn\",\n\"test-iceberg-api1\" \n  ],\n\t\"type\": \"VIRTUAL_DATASET\",\n\t\"sql\": \"select * from \"table\" \",\n\t\"sqlContext\": [\"testingS3\", \"fybric-objectstorage-iceberg-demo\", \"warehouse\", \"db\"]\n}"
    newVDSName = "test-iceberg-api3"
    dataVDS = {
        "entityType": "dataset",
        "path": [
            "Space-api",
            newVDSName,
        ],
	    "type": "VIRTUAL_DATASET",
	    "sql": 'select _c1 from "table" ',
	    "sqlContext": ["testingS3", "fybric-objectstorage-iceberg-demo", "warehouse", "db"]
    }
    
    # headers = {
    #     'Authorization': "_dremiogavgbr3fnpm425qt5rikobgqj8",
    #     'Content-Type': "application/json"
    # }
    # response = requests.request("POST", url, data=json.dumps(dataVDS), headers=headers)
    response = api_post(dremioServer, "catalog", dataVDS, auth_headers)
    print(response)

   

