import json
import click
from typing import List
from cli.printers.base_printer import BasePrinter
from cli.models import DocumentDetections
from cyclient.models import DetectionSchema


class JsonPrinter(BasePrinter):

    scan_id: str

    def __init__(self, context: click.Context):
        super().__init__(context)
        self.scan_id = context.obj.get('scan_id')

    def print_results(self, results: List[DocumentDetections]):
        detections = [detection for document_detections in results for detection in document_detections.detections]
        detections_schema = DetectionSchema(many=True)
        detections_dict = detections_schema.dump(detections)
        json_result = self._get_json_result(detections_dict)
        click.secho(json_result)

    def _get_json_result(self, detections):
        result = {
            'scan_id': str(self.scan_id),
            'detections': detections
        }

        return json.dumps(result, indent=4)
