import argparse
import json
import requests
from time import sleep

def api_get(server, endpoint=None, body=None, headers=None):
    """" Run GET command """
    return json.loads(requests.get(url='{server}/api/v3/{endpoint}'.format(server=server, endpoint=endpoint), headers=headers, data=json.dumps(body)).text)

def api_post(server, endpoint=None, body=None, headers=None):
    """" Run POST command """
    text = requests.request("POST", '{server}/api/v3/{endpoint}'.format(server=server, endpoint=endpoint), headers=headers, data=json.dumps(body)).text

    # a post may return no data
    if (text):
        return json.loads(text)
    else:
        return None

def login(server, username, password, headers=None):
    """" Login to Dremio using the given username and password """
    loginData = {'userName': username, 'password': password}
    response = requests.post('{server}/apiv2/login'.format(server=server), headers=headers, data=json.dumps(loginData))
    data = json.loads(response.text)

    # retrieve the login token
    token = data['token']
    return {'Content-Type': 'application/json', 'Authorization': '_dremio{authToken}'.format(authToken=token)}

def wait_for_query(server, auth_headers, job_id):
    """ Wait for the query to finish """
    result_endpoint = "job/{id}".format(id=job_id)
    count = 0
    while count < 30:
        results = api_get(server, endpoint=result_endpoint, headers=auth_headers)
        if results["jobState"] == "COMPLETED":
            break
        count += 1
        sleep(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Query the Iceberg table via the dremio cluster.')
    parser.add_argument('--query', type=str, help='The query, for example: \'{"sql": "SELECT _c0 FROM \\"Space-api\\".\\"sample-iceberg-vds\\""}\'')
    args = vars(parser.parse_args())
    username = "adminUser"
    password = "adminPwd1"
    json_headers = {'content-type': 'application/json'}
    dremio_server = 'http://localhost:9047'
    
    # Login to Dremio with admin user
    auth_headers = login(dremio_server, username, password, json_headers)

    #query = {'sql': 'SELECT _c0 FROM \"Space-api\".\"sample-iceberg-vds\"'}
    query = json.loads(args["query"])
    
    response = api_post(dremio_server, "sql", query, auth_headers)
    wait_for_query(dremio_server, auth_headers, response["id"])
    result_endpoint = "job/{id}/results".format(id=response["id"])
    results = api_get(dremio_server, endpoint=result_endpoint, headers=auth_headers)
    print(results)
