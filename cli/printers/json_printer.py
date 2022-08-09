import json
import click
from typing import List
from cli.printers.base_printer import BasePrinter
from cli.models import DocumentDetections
from cyclient.models import DetectionSchema


class JsonPrinter(BasePrinter):
    def print_results(self, context: click.Context, results: List[DocumentDetections]):
        detections = [detection for document_detections in results for detection in document_detections.detections]
        detections_schema = DetectionSchema(many=True)
        detections_dict = detections_schema.dump(detections)
        json_result = self._get_json_result(context, detections_dict)
        click.secho(json_result)

    def _get_json_result(self, context, detections):
        scan_id = context.obj.get('scan_id')
        result = {
            'scan_id': str(scan_id),
            'detections': detections
        }

        return json.dumps(result, indent=4)
