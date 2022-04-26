import argparse
import base64
import json
import socket
from time import sleep
import yaml
import requests

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

    return parser.parse_args()



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

    username = "newUser"
    password = "testpassword123"
    json_headers = {'content-type': 'application/json'}
    dremioServer = 'http://localhost:9047'
    # dremioServer = 'http://dremio-client.fybrik-blueprints.svc.cluster.local:9047'
    

    auth_headers = login(dremioServer, username, password, json_headers)
    print("headers")
    print(auth_headers)




    # Get the columns of the new source
    sql_path = '"Space-api"."sample-iceberg-vds"'
    print(sql_path)
    print("dataSQL")
    dataSQL = {
        "sql": 'SELECT _c0 FROM ' + sql_path
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
    print(response)


