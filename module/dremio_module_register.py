import json
from time import sleep
import requests
from fybrik_python_logging import init_logger, logger
import utils


def register_admin_user(dremio_server, admin_user, admin_password):
    data_user = {
        "userName": admin_user,
        "firstName": "user",
        "lastName": "admin",
        "email": "test@test.com",
        "password": admin_password,
    }
    headers = {'Content-Type': 'application/json', 'Authorization': '_dremionull'}
    response = requests.request("PUT", dremio_server + '/apiv2/bootstrap/firstuser', data=json.dumps(data_user), headers=headers)
    logger.debug("register user response: %s", response.text)


def create_s3_source(dremio_server, auth_headers, creds, endpoint, source_name):
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
    response = utils.api_post(dremio_server, "catalog", auth_headers, data_s3)
    logger.debug("new source response: %s", response)


def promote_folder(dremio_server, auth_headers, path, source_name):
    path_list = path.split('/')
    path_list = [source_name] + path_list
    dataPromote = {
        "entityType": "dataset",
        "id": "dremio:/" + source_name + "/" + path,
        "path": path_list,
        "type": "PHYSICAL_DATASET",
        "format": {
            "type": "Iceberg"
        }
    }
    promote_url = source_name + '%2F' + '%2F'.join(path_list[1:])
    response = utils.api_post(dremio_server, "catalog/dremio%3A%2F" + promote_url, auth_headers, dataPromote)
    logger.debug("promote response: %s", response)
    return path_list


def get_table_columns(dremio_server, auth_headers, sql_path):
    dataSQL = {
        "sql": 'SELECT * FROM "' + sql_path + 'LIMIT 0'
    }
    response = utils.api_post(dremio_server, "sql", auth_headers, dataSQL)
    job_id = response.get("id")
    
    response = utils.api_get(dremio_server, "job/"+job_id, auth_headers, dataSQL)
    while(response.get("jobState") != "COMPLETED"):
        logger.info("wait for job")
        response = utils.api_get(dremio_server, "job/"+job_id, auth_headers, dataSQL)
        sleep(10)
    response = utils.api_get(dremio_server, "job/"+job_id+"/results", auth_headers, dataSQL)
    col_names = [elem.get("name") for elem in response.get("schema")]
    logger.debug("Table's columns: %s", col_names)
    return col_names


def get_policy_query(transformation_cols, sql_path, col_names):
    request_cols = [col for col in col_names if col not in transformation_cols]
    if len(request_cols) < 1:
        logger.debug("empty dataset")
        return ""
    requested_cols_string = request_cols[0]
    for col in request_cols[1:]:
        add_col = ", " + col
        requested_cols_string += add_col
    sql_vds = "select " + requested_cols_string + ' from "' + sql_path
    logger.debug("SQL to build VDS: %s", sql_vds)
    return sql_vds


def create_VDS(dremio_server, auth_headers, path_list, sql_vds, newVDSName):
    dataVDS = {
        "entityType": "dataset",
        "path": [
            "Space-api",
            newVDSName,
        ],
	    "type": "VIRTUAL_DATASET",
	    "sql": sql_vds,
	    "sqlContext": path_list
    }
    response = utils.api_post(dremio_server, "catalog", auth_headers, dataVDS)
    logger.debug("Create VDS response: %s", response)


def create_new_user(dremio_server, auth_headers):
    dataNewUser = {
        "name": "newUser",
        "firstName": "first",
        "password": "testpassword123",
    }
    response = utils.api_post(dremio_server, "user", auth_headers, dataNewUser)
    logger.debug("Create new user response: %s", response)


if __name__ == "__main__":
    json_headers = {'content-type': 'application/json'}
    # Set log level
    init_logger("TRACE", "123", 'dremio-module-register')
    # Get the dataset details from configuration
    conf, dremio_host, dremio_port = utils.get_details_from_conf()
    dremio_server = "http://" + dremio_host + ":" + str(dremio_port)
    transformation = conf['transformation']
    transformation_cols = conf['transformation_cols']
    asset_creds = conf['asset_creds']
    dremio_creds = conf['dremio_creds']
    username = dremio_creds[0]
    password = dremio_creds[1]
    logger.debug("dremio username: " + username + " dremio password: " + password)

    endpoint = conf['endpoint_url']
    path = conf['path']
    if "://" in endpoint:
        endpoint = endpoint.split("://")[1]
    # Wait for dremio to be ready
    utils.wait_dremio(dremio_host, dremio_port)
    # Register the admin user
    register_admin_user(dremio_server, username, password)
    # Login to Dremio with admin user
    auth_headers = utils.login(dremio_server, username, password, json_headers)

    # Create a new source from an s3 bucket
    source_name = "sample-iceberg"
    create_s3_source(dremio_server, auth_headers, asset_creds, endpoint, source_name)

    # Get data folder path
    response = utils.api_get(dremio_server, endpoint="catalog/by-path/{name}/{path}".format(name=source_name, path=path), headers=auth_headers)
    logger.debug("Get path of the data folder: %s", response)

    # Promote a folder to dataset
    path_list = promote_folder(dremio_server, auth_headers, path, source_name)

    # Get the columns of the new source
    sql_path = source_name + '"."' + '"."'.join(path_list[1:]) + '"'
    col_names = get_table_columns(dremio_server, auth_headers, sql_path)

    # Get the sql query from the policies
    sql_vds = get_policy_query(transformation_cols, sql_path, col_names)

    payloadSpace = {
        "entityType": "space",
        "name": "Space-api"
    }
    response = utils.api_post(dremio_server, "catalog", auth_headers, payloadSpace)
    logger.debug("Create space: %s", response)
    
    # Create a virtual dataset that represents the source dataset after applying the policies
    newVDSName = "sample-iceberg-vds"
    create_VDS(dremio_server, auth_headers, path_list, sql_vds, newVDSName)

    # Add a new user
    create_new_user(dremio_server, auth_headers)

    logger.info("Finished configuring Dremio")
