from typing import Optional

import responses
from responses import matchers

from cycode.cyclient.import_sbom_client import ImportSbomClient


def get_import_sbom_url(import_sbom_client: ImportSbomClient) -> str:
    api_url = import_sbom_client.client.api_url
    service_url = ImportSbomClient.IMPORT_SBOM_REQUEST_PATH
    return f'{api_url}/{service_url}'


def get_import_sbom_response(url: str, status: int = 201) -> responses.Response:
    json_response = {'message': 'SBOM imported successfully'}
    return responses.Response(method=responses.POST, url=url, json=json_response, status=status)


def get_member_details_url(import_sbom_client: ImportSbomClient) -> str:
    api_url = import_sbom_client.client.api_url
    service_url = ImportSbomClient.GET_USER_ID_REQUEST_PATH
    return f'{api_url}/{service_url}'


def get_member_details_response(
    url: str, email: str, external_id: Optional[str] = None, status: int = 200
) -> responses.Response:
    items = []
    if external_id:
        items = [{'external_id': external_id, 'email': email}]

    json_response = {
        'items': items,
        'page_size': 10,
        'next_page_token': None,
    }

    return responses.Response(
        method=responses.GET,
        url=url,
        json=json_response,
        status=status,
        match=[matchers.query_param_matcher({'email': email})],
    )


def mock_import_sbom_responses(
    responses_module: responses,
    import_sbom_client: ImportSbomClient,
    status: int = 201,
) -> None:
    """Mock the basic SBOM import endpoint"""
    responses_module.add(get_import_sbom_response(get_import_sbom_url(import_sbom_client), status))


def mock_member_details_response(
    responses_module: responses,
    import_sbom_client: ImportSbomClient,
    email: str,
    external_id: Optional[str] = None,
    status: int = 200,
) -> None:
    """Mock the member details lookup endpoint"""
    responses_module.add(
        get_member_details_response(get_member_details_url(import_sbom_client), email, external_id, status)
    )
