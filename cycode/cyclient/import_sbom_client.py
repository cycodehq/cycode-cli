import dataclasses
from pathlib import Path
from typing import Optional

from requests import Response

from cycode.cli.cli_types import BusinessImpactOption
from cycode.cli.exceptions.custom_exceptions import RequestHttpError
from cycode.cyclient import models
from cycode.cyclient.cycode_client_base import CycodeClientBase


@dataclasses.dataclass
class ImportSbomParameters:
    Name: str
    Vendor: str
    BusinessImpact: BusinessImpactOption
    Labels: Optional[list[str]]
    Owners: Optional[list[str]]

    def _owners_to_ids(self) -> list[str]:
        return []

    def to_request_form(self) -> dict:
        form_data = {}
        for field in dataclasses.fields(self):
            key = field.name
            val = getattr(self, key)
            if val is None or len(val) == 0:
                continue
            if isinstance(val, list):
                form_data[f'{key}[]'] = val
            else:
                form_data[key] = val
        return form_data


class ImportSbomClient:
    IMPORT_SBOM_REQUEST_PATH: str = 'v4/sbom/import'
    GET_USER_ID_REQUEST_PATH: str = 'v4/members'

    def __init__(self, client: CycodeClientBase) -> None:
        self.client = client

    def request_sbom_import_execution(self, params: ImportSbomParameters, file_path: Path) -> None:
        if params.Owners:
            owners_ids = self.get_owners_user_ids(params.Owners)
            params.Owners = owners_ids

        form_data = params.to_request_form()

        with open(file_path.absolute(), 'rb') as f:
            request_args = {
                'url_path': self.IMPORT_SBOM_REQUEST_PATH,
                'data': form_data,
                'files': {'File': f},
            }

            response = self.client.post(**request_args)

        if response.status_code != 201:
            raise RequestHttpError(response.status_code, response.text, response)

    def get_owners_user_ids(self, owners: list[str]) -> list[str]:
        return [self._get_user_id_by_email(owner) for owner in owners]

    def _get_user_id_by_email(self, email: str) -> str:
        request_args = {'url_path': self.GET_USER_ID_REQUEST_PATH, 'params': {'email': email}}

        response = self.client.get(**request_args)
        member_details = self.parse_requested_member_details_response(response)

        if not member_details.items:
            raise Exception(
                f"Failed to find user with email '{email}'. Verify this email is registered to Cycode platform"
            )
        return member_details.items.pop(0).external_id

    @staticmethod
    def parse_requested_member_details_response(response: Response) -> models.MemberDetails:
        return models.RequestedMemberDetailsResultSchema().load(response.json())
