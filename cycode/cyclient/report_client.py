import dataclasses
import json
from typing import List, Optional

from requests import Response

from cycode.cli.files_collector.models.in_memory_zip import InMemoryZip
from cycode.cyclient import models
from cycode.cyclient.cycode_client_base import CycodeClientBase


@dataclasses.dataclass
class ReportParameters:
    entity_type: str
    sbom_report_type: str
    sbom_version: str
    output_format: str
    include_vulnerabilities: bool
    include_dev_dependencies: bool

    def to_dict(self, *, without_entity_type: bool) -> dict:
        model_dict = dataclasses.asdict(self)
        if without_entity_type:
            del model_dict['entity_type']
        return model_dict

    def to_json(self, *, without_entity_type: bool) -> str:
        return json.dumps(self.to_dict(without_entity_type=without_entity_type))


class ReportClient:
    SERVICE_NAME: str = 'report'
    CREATE_SBOM_REPORT_REQUEST_PATH: str = 'api/v2/report/{report_type}/sbom'
    GET_EXECUTIONS_STATUS_PATH: str = 'api/v2/report/{report_id}/executions'

    DOWNLOAD_REPORT_PATH: str = 'files/api/v1/file/sbom/{file_name}'  # not in the report service

    def __init__(self, client: CycodeClientBase, hide_response_log: bool = True) -> None:
        self.client = client
        self._hide_response_log = hide_response_log

    def request_sbom_report(
        self, params: ReportParameters, zip_file: InMemoryZip = None, repository_url: Optional[str] = None
    ) -> models.SbomReport:
        report_type = 'zipped-file' if zip_file else 'repository-url'
        url_path = f'{self.SERVICE_NAME}/{self.CREATE_SBOM_REPORT_REQUEST_PATH}'.format(report_type=report_type)

        # entity type required only for zipped-file
        request_data = {'report_parameters': params.to_json(without_entity_type=zip_file is None)}
        if repository_url:
            request_data['repository_url'] = repository_url

        request_args = {
            'url_path': url_path,
            'data': request_data,
            'hide_response_content_log': self._hide_response_log,
        }

        if zip_file:
            request_args['files'] = {'file': ('sca_files.zip', zip_file.read())}

        response = self.client.post(**request_args)
        return self.parse_requested_sbom_report_response(response)

    def get_execution_status(self, report_id: int) -> List[models.SbomReportStatus]:
        url_path = f'{self.SERVICE_NAME}/{self.GET_EXECUTIONS_STATUS_PATH}'.format(report_id=report_id)
        response = self.client.get(url_path=url_path)
        return self.parse_execution_status_response(response)

    def get_file_content(self, file_name: str) -> str:
        response = self.client.get(
            url_path=self.DOWNLOAD_REPORT_PATH.format(file_name=file_name), params={'include_hidden': True}
        )
        return response.text

    @staticmethod
    def parse_requested_sbom_report_response(response: Response) -> models.SbomReport:
        return models.RequestedSbomReportResultSchema().load(response.json())

    @staticmethod
    def parse_execution_status_response(response: Response) -> List[models.SbomReportStatus]:
        return models.SbomReportExecutionStatusResultSchema().load(response.json(), many=True)
