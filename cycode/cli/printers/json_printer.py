import json
from typing import TYPE_CHECKING, Dict, List, Optional

import click

from cycode.cli.models import CliError, CliResult
from cycode.cli.printers.printer_base import PrinterBase
from cycode.cyclient.models import DetectionSchema

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult


class JsonPrinter(PrinterBase):
    def print_result(self, result: CliResult) -> None:
        result = {'result': result.success, 'message': result.message}

        click.echo(self.get_data_json(result))

    def print_error(self, error: CliError) -> None:
        result = {'error': error.code, 'message': error.message}

        click.echo(self.get_data_json(result))

    def print_scan_results(
        self, local_scan_results: List['LocalScanResult'], errors: Optional[Dict[str, 'CliError']] = None
    ) -> None:
        detections = []
        for local_scan_result in local_scan_results:
            for document_detections in local_scan_result.document_detections:
                detections.extend(document_detections.detections)

        detections_dict = DetectionSchema(many=True).dump(detections)

        inlined_errors = []
        if errors:
            # FIXME(MarshalX): we don't care about scan IDs in JSON output due to clumsy JSON root structure
            inlined_errors = [err._asdict() for err in errors.values()]

        click.echo(self._get_json_scan_result(detections_dict, inlined_errors))

    def _get_json_scan_result(self, detections: dict, errors: List[dict]) -> str:
        result = {
            'scan_id': 'DEPRECATED',  # FIXME(MarshalX): we need change JSON struct to support multiple scan results
            'detections': detections,
            'errors': errors,
        }

        return self.get_data_json(result)

    @staticmethod
    def get_data_json(data: dict) -> str:
        # ensure_ascii is disabled for symbols like "`". Eg: `cycode scan`
        return json.dumps(data, indent=4, ensure_ascii=False)
