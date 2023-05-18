import json
from typing import List

import click

from cycode.cli.models import DocumentDetections, CliResult, CliError
from cycode.cli.printers.base_printer import BasePrinter
from cycode.cyclient.models import DetectionSchema


class JsonPrinter(BasePrinter):
    def __init__(self, context: click.Context):
        super().__init__(context)
        self.scan_id = context.obj.get('scan_id')

    def print_result(self, result: CliResult) -> None:
        result = {
            'result': result.success,
            'message': result.message
        }

        click.secho(self.get_data_json(result))

    def print_error(self, error: CliError) -> None:
        result = {
            'error': error.code,
            'message': error.message
        }

        click.secho(self.get_data_json(result))

    def print_scan_results(self, results: List[DocumentDetections]) -> None:
        detections = []
        for result in results:
            detections.extend(result.detections)

        detections_dict = DetectionSchema(many=True).dump(detections)

        click.secho(self._get_json_scan_result(detections_dict))

    def _get_json_scan_result(self, detections: dict) -> str:
        result = {
            'scan_id': str(self.scan_id),
            'detections': detections
        }

        return self.get_data_json(result)

    @staticmethod
    def get_data_json(data: dict) -> str:
        # ensure_ascii is disabled for symbols like "`". Eg: `cycode scan`
        return json.dumps(data, indent=4, ensure_ascii=False)
