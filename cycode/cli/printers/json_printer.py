import json
from typing import TYPE_CHECKING, Optional

from cycode.cli.models import CliError, CliResult
from cycode.cli.printers.printer_base import PrinterBase
from cycode.cyclient.models import DetectionSchema

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult


class JsonPrinter(PrinterBase):
    def print_result(self, result: CliResult) -> None:
        result = {'result': result.success, 'message': result.message, 'data': result.data}

        self.console.print_json(self.get_data_json(result))

    def print_error(self, error: CliError) -> None:
        result = {'error': error.code, 'message': error.message}

        self.console.print_json(self.get_data_json(result))

    def print_scan_results(
        self, local_scan_results: list['LocalScanResult'], errors: Optional[dict[str, 'CliError']] = None
    ) -> None:
        scan_ids = []
        report_urls = []
        detections = []
        aggregation_report_url = self.ctx.obj.get('aggregation_report_url')
        if aggregation_report_url:
            report_urls.append(aggregation_report_url)

        for local_scan_result in local_scan_results:
            scan_ids.append(local_scan_result.scan_id)

            if not aggregation_report_url and local_scan_result.report_url:
                report_urls.append(local_scan_result.report_url)
            for document_detections in local_scan_result.document_detections:
                detections.extend(document_detections.detections)

        detections_dict = DetectionSchema(many=True).dump(detections)

        inlined_errors = []
        if errors:
            # FIXME(MarshalX): we don't care about scan IDs in JSON output due to clumsy JSON root structure
            inlined_errors = [err._asdict() for err in errors.values()]

        self.console.print_json(self._get_json_scan_result(scan_ids, detections_dict, report_urls, inlined_errors))

    def _get_json_scan_result(
        self, scan_ids: list[str], detections: dict, report_urls: list[str], errors: list[dict]
    ) -> str:
        result = {
            'scan_ids': scan_ids,
            'detections': detections,
            'report_urls': report_urls,
            'errors': errors,
        }

        return self.get_data_json(result)

    @staticmethod
    def get_data_json(data: dict) -> str:
        # ensure_ascii is disabled for symbols like "`". Eg: `cycode scan`
        return json.dumps(data, ensure_ascii=False)
