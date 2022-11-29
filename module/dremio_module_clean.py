from fybrik_python_logging import init_logger, logger
import utils


def get_resource_id(dremio_server, path, auth_headers):
    response = utils.api_get(dremio_server, "catalog/by-path/" + path, auth_headers, "")
    print(response)
    if 'id' in response:
        return response['id']


def delete_resource(dremio_server, id, auth_headers):
    # TODO: Check response
    response = utils.api_delete(dremio_server, "catalog/" + id, auth_headers)
    

if __name__ == "__main__":
    init_logger("TRACE", "123", 'dremio-module-cleanup')
    
    conf, dremio_host, dremio_port = utils.get_details_from_conf()
    dremio_server = "http://" + dremio_host + ":" + str(dremio_port)
    transformation = conf['transformation']
    transformation_cols = conf['transformation_cols']
    asset_creds = conf['asset_creds']
    dremio_creds = conf['dremio_creds']
    username = dremio_creds[0]
    password = dremio_creds[1]
    json_headers = {'content-type': 'application/json'}

    # Wait for dremio to be ready
    utils.wait_dremio(dremio_host, dremio_port)
    # Login to Dremio with admin user
    auth_headers = utils.login(dremio_server, username, password, json_headers)
    
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
    logger.info("Finished cleanup")
