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
        json_result = json.dumps(detections_dict, indent=4)
        click.secho(json_result, fg='white')
