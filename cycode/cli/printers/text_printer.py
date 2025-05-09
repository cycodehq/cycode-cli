from typing import TYPE_CHECKING, Optional

from cycode.cli import consts
from cycode.cli.cli_types import SeverityOption
from cycode.cli.models import CliError, CliResult, Document
from cycode.cli.printers.printer_base import PrinterBase
from cycode.cli.printers.utils.code_snippet_syntax import get_code_snippet_syntax, get_detection_line
from cycode.cli.printers.utils.detection_data import get_detection_title
from cycode.cli.printers.utils.detection_ordering.common_ordering import sort_and_group_detections_from_scan_result

if TYPE_CHECKING:
    from cycode.cli.models import Detection, LocalScanResult


class TextPrinter(PrinterBase):
    def print_result(self, result: CliResult) -> None:
        color = 'default'
        if not result.success:
            color = 'red'

        self.console.print(result.message, style=color)

        if not result.data:
            return

        self.console.print('\nAdditional data:', style=color)
        for name, value in result.data.items():
            self.console.print(f'- {name}: {value}', style=color)

    def print_error(self, error: CliError) -> None:
        self.console.print(f'[red]Error: {error.message}[/]', highlight=False)

    def print_scan_results(
        self, local_scan_results: list['LocalScanResult'], errors: Optional[dict[str, 'CliError']] = None
    ) -> None:
        if not errors and all(result.issue_detected == 0 for result in local_scan_results):
            self.console.print(self.NO_DETECTIONS_MESSAGE)
            return

        detections, _ = sort_and_group_detections_from_scan_result(local_scan_results)
        for detection, document in detections:
            self.__print_document_detection(document, detection)

        self.print_scan_results_summary(local_scan_results)
        self.print_report_urls_and_errors(local_scan_results, errors)

    def __print_document_detection(self, document: 'Document', detection: 'Detection') -> None:
        self.__print_detection_summary(detection, document.path)
        self.__print_detection_code_segment(detection, document)
        self._print_new_line()

    def _print_new_line(self) -> None:
        self.console.line()

    def __print_detection_summary(self, detection: 'Detection', document_path: str) -> None:
        title = get_detection_title(self.scan_type, detection)

        severity = SeverityOption(detection.severity) if detection.severity else 'N/A'
        severity_icon = SeverityOption.get_member_emoji(detection.severity) if detection.severity else ''

        line_no = get_detection_line(self.scan_type, detection) + 1
        clickable_document_path = f'[u]{document_path}:{line_no}[/]'

        detection_commit_id = detection.detection_details.get('commit_id')
        detection_commit_id_message = f'\nCommit SHA: {detection_commit_id}' if detection_commit_id else ''

        self.console.print(
            severity_icon,
            severity,
            f'violation: [b bright_red]{title}[/]{detection_commit_id_message}\n',
            *self.__get_intermediate_summary_lines(detection),
            f'[dodger_blue1]File: {clickable_document_path}[/]',
        )

    def __get_intermediate_summary_lines(self, detection: 'Detection') -> list[str]:
        intermediate_summary_lines = []

        if self.scan_type == consts.SCA_SCAN_TYPE:
            intermediate_summary_lines.extend(self.__get_sca_related_summary_lines(detection))

        return intermediate_summary_lines

    @staticmethod
    def __get_sca_related_summary_lines(detection: 'Detection') -> list[str]:
        summary_lines = []

        if detection.has_alert:
            patched_version = detection.detection_details['alert'].get('first_patched_version')
            patched_version = patched_version or 'Not fixed'

            summary_lines.append(f'First patched version: [cyan]{patched_version}[/]\n')
        else:
            package_license = detection.detection_details.get('license', 'N/A')
            summary_lines.append(f'License: [cyan]{package_license}[/]\n')

        return summary_lines

    def __print_detection_code_segment(self, detection: 'Detection', document: Document) -> None:
        self.console.print(
            get_code_snippet_syntax(
                self.scan_type,
                self.command_scan_type,
                detection,
                document,
                obfuscate=not self.show_secret,
            )
        )

    def print_report_urls_and_errors(
        self, local_scan_results: list['LocalScanResult'], errors: Optional[dict[str, 'CliError']] = None
    ) -> None:
        report_urls = [scan_result.report_url for scan_result in local_scan_results if scan_result.report_url]

        self.print_report_urls(report_urls, self.ctx.obj.get('aggregation_report_url'))
        if not errors:
            return

        self.console.print(self.FAILED_SCAN_MESSAGE)
        for scan_id, error in errors.items():
            self.console.print(f'- {scan_id}: ', end='')
            self.print_error(error)

    def print_report_urls(self, report_urls: list[str], aggregation_report_url: Optional[str] = None) -> None:
        if not report_urls and not aggregation_report_url:
            return

        # Prioritize aggregation report URL; if report urls is only one, use it instead
        single_url = report_urls[0] if len(report_urls) == 1 else None
        single_url = aggregation_report_url or single_url
        if single_url:
            self.console.print(f'[b]Report URL:[/] {single_url}')
            return

        # If there are multiple report URLs, print them all
        self.console.print('[b]Report URLs:[/]')
        for report_url in report_urls:
            self.console.print(f'- {report_url}')
