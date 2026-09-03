import json
from typing import TYPE_CHECKING, Optional

from cycode.cli.models import CliError, CliResult
from cycode.cli.printers.printer_base import PrinterBase
from cycode.cli.printers.utils import binary_report
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

        self._print_degradation_warning_to_stderr()
        self.console.print_json(
            self._get_json_scan_result(
                scan_ids, detections_dict, report_urls, inlined_errors, self._get_binary_section(local_scan_results)
            )
        )

    def _print_degradation_warning_to_stderr(self) -> None:
        """The human running this still deserves the warning; stdout still has to stay parseable.

        The same fact is available machine-readably as ``binary.partial``, so a CI job never has to read stderr.
        """
        collection = binary_report.get_binary_collection(self.ctx)
        if collection is None or not binary_report.should_warn_about_degradation(self.ctx, collection):
            return

        for line in binary_report.get_degradation_lines(collection):
            self.console_err.print(f'[yellow]:warning: {line}[/]', highlight=False)

    def _get_binary_section(self, local_scan_results: list['LocalScanResult']) -> Optional[dict]:
        """Coverage numbers a CI job can assert on, so a team can gate on identification rather than guess at it."""
        collection = binary_report.get_binary_collection(self.ctx)
        if collection is None:
            return None

        section = {
            'identified': collection.identified_count,
            'low_confidence_components': collection.low_confidence_count,
            'unidentified': [entry._asdict() for entry in binary_report.get_unidentified(collection)],
            'low_confidence_detections': binary_report.count_low_confidence(self.ctx, local_scan_results),
            'resolver_available': collection.resolver_available,
            'partial': binary_report.should_warn_about_degradation(self.ctx, collection),
        }

        # present only when --include-declared was given, so its absence means "not asked", never "none found"
        if collection.include_declared:
            section['declared'] = {
                'components': collection.declared_count,
                'transitive': collection.transitive_count,
                'unresolved': [entry._asdict() for entry in binary_report.get_declared_unresolved(collection)],
            }

        return section

    def _get_json_scan_result(
        self,
        scan_ids: list[str],
        detections: dict,
        report_urls: list[str],
        errors: list[dict],
        binary: Optional[dict] = None,
    ) -> str:
        result = {
            'scan_ids': scan_ids,
            'detections': detections,
            'report_urls': report_urls,
            'errors': errors,
        }

        # additive: nothing existing changes shape, and the keys are absent entirely for non-binary scans
        if binary is not None:
            result['unidentified'] = binary['unidentified']
            result['binary'] = binary

        return self.get_data_json(result)

    @staticmethod
    def get_data_json(data: dict) -> str:
        # ensure_ascii is disabled for symbols like "`". Eg: `cycode scan`
        return json.dumps(data, ensure_ascii=False)
