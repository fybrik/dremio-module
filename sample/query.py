import argparse
import json
import sys
import os
 
current = os.path.dirname(os.path.realpath(__file__)) 
parent = os.path.dirname(current)
sys.path.append(parent)
import module.utils as utils
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Query the Iceberg table via the dremio cluster.')
    parser.add_argument('--query', type=str, help='The query, for example: \'{"sql": "SELECT _c0 FROM \\"Space-api\\".\\"sample-iceberg-vds\\""}\'')
    args = vars(parser.parse_args())
    username = "adminUser"
    password = "adminPwd1"
    json_headers = {'content-type': 'application/json'}
    dremio_server = 'http://localhost:9047'
    
    # Login to Dremio with admin user
    auth_headers = utils.login(dremio_server, username, password, json_headers)

    #query = {'sql': 'SELECT _c0 FROM \"Space-api\".\"sample-iceberg-vds\"'}
    if args["query"]:
        query = json.loads(args["query"])
    else:
        # Setup a default query
        query = {'sql': 'SELECT _c0 FROM \"Space-api\".\"sample-iceberg-vds\"'} 
    response = utils.api_post(dremio_server, "sql", auth_headers, query)
    utils.wait_for_query(dremio_server, auth_headers, response["id"])
    result_endpoint = "job/{id}/results".format(id=response["id"])
    results = utils.api_get(dremio_server, endpoint=result_endpoint, headers=auth_headers)
    print(results)
