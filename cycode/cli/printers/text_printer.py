from typing import TYPE_CHECKING, Optional

from cycode.cli import consts
from cycode.cli.cli_types import SeverityOption
from cycode.cli.models import CliError, CliResult, Document
from cycode.cli.printers.printer_base import PrinterBase
from cycode.cli.printers.utils import binary_report
from cycode.cli.printers.utils.code_snippet_syntax import get_code_snippet_syntax, get_detection_line
from cycode.cli.printers.utils.detection_data import get_detection_title
from cycode.cli.printers.utils.detection_ordering.common_ordering import sort_and_group_detections_from_scan_result
from cycode.cli.printers.utils.sca_policy_details import get_sca_policy_details

if TYPE_CHECKING:
    from cycode.cli.files_collector.binary.collector import BinaryCollectionResult
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
            # a clean scan still owes the user its coverage numbers: "no issues" and "we could not read half of it"
            # are very different statements
            self.print_binary_report(local_scan_results)
            return

        detections, _ = sort_and_group_detections_from_scan_result(local_scan_results)
        for detection, document in detections:
            self.__print_document_detection(document, detection)

        self.print_binary_report(local_scan_results)
        self.print_scan_results_summary(local_scan_results)
        self.print_report_urls_and_errors(local_scan_results, errors)

    def print_binary_report(self, local_scan_results: list['LocalScanResult']) -> None:
        """The unidentified section, the degradation warning and the coverage line.

        Printed after findings and before the summary. Silent for every scan that is not a binary scan.
        """
        collection = binary_report.get_binary_collection(self.ctx)
        if collection is None:
            return

        if binary_report.should_warn_about_degradation(self.ctx, collection):
            self._print_degradation_warning(collection)

        self._print_unidentified_section(collection)
        self._print_declared_unresolved_section(collection)
        self._print_low_confidence_note(local_scan_results)
        self._print_coverage_summary(collection, local_scan_results)

    def _print_degradation_warning(self, collection: 'BinaryCollectionResult') -> None:
        self.console_err.line()
        for line in binary_report.get_degradation_lines(collection):
            self.console_err.print(f'[yellow]:warning: {line}[/]', highlight=False)

    def _print_unidentified_section(self, collection: 'BinaryCollectionResult') -> None:
        unidentified = binary_report.get_unidentified(collection)
        if not unidentified:
            return

        self.console.line()
        self.console.print(f'[bold]UNIDENTIFIED ({len(unidentified)})[/]')
        for entry in unidentified:
            # the name comes from inside an untrusted archive; it is markup- and control-character-sanitised
            self.console.print(f'  {binary_report.for_display(entry.logical_path)}', highlight=False)
            self.console.print(
                f'    [dim]sha1 {entry.sha1[:8]}...  {binary_report.format_size(entry.size)}[/]', highlight=False
            )

    def _print_declared_unresolved_section(self, collection: 'BinaryCollectionResult') -> None:
        unresolved = binary_report.get_declared_unresolved(collection)
        if not unresolved:
            return

        self.console.line()
        self.console.print(f'[bold]DECLARED, VERSION UNRESOLVED ({len(unresolved)})[/]')
        for entry in unresolved:
            # every field comes from inside an untrusted archive
            coordinate = binary_report.for_display(entry.coordinate)
            expression = binary_report.for_display(entry.version_expression)
            declared_by = binary_report.for_display(entry.declared_by)
            self.console.print(f'  {coordinate} {expression}', highlight=False)
            self.console.print(f'    [dim]declared by {declared_by}[/]', highlight=False)
            self.console.print(f'    [dim]{binary_report.for_display(entry.reason)}[/]', highlight=False)

    def _print_low_confidence_note(self, local_scan_results: list['LocalScanResult']) -> None:
        low_confidence = binary_report.count_low_confidence(self.ctx, local_scan_results)
        if not low_confidence:
            return

        self.console.line()
        self.console.print(
            f'[dim]{low_confidence} finding(s) come from a component identified by manifest attributes only. '
            f'They are marked low confidence and do not affect the exit code.[/]',
            highlight=False,
        )

    def _print_coverage_summary(
        self, collection: 'BinaryCollectionResult', local_scan_results: list['LocalScanResult']
    ) -> None:
        vulnerabilities = binary_report.count_detections(local_scan_results)
        self.console.line()
        self.console.print(f'[bold]{binary_report.get_coverage_summary(collection, vulnerabilities)}[/]')

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
            *self._get_binary_evidence_lines(detection),
        )

    def _get_binary_evidence_lines(self, detection: 'Detection') -> list[str]:
        """Where inside the artifact the component sits, and how confidently we named it."""
        evidence = binary_report.get_detection_evidence(self.ctx, detection)
        if evidence is None:
            return []

        location = binary_report.for_display(evidence.logical_path)
        if evidence.is_declared:
            # the component is not in the artifact at all; saying "found in" would be false
            return [
                f'\n[dodger_blue1]Declared by: {location}[/]',
                f'\n[dim]Presence: {binary_report.for_display(evidence.presence_summary)}[/]',
            ]

        lines = [f'\n[dodger_blue1]Found in: {location}[/]']
        if evidence.is_ambiguous:
            lines.append(f'\n[yellow]Identified by: {evidence.evidence} (low confidence, does not affect exit code)[/]')
        else:
            lines.append(f'\n[dim]Identified by: {evidence.evidence} (exact)[/]')

        return lines

    def __get_intermediate_summary_lines(self, detection: 'Detection') -> list[str]:
        intermediate_summary_lines = []

        if self.scan_type == consts.SCA_SCAN_TYPE:
            intermediate_summary_lines.extend(self.__get_sca_related_summary_lines(detection))

        return intermediate_summary_lines

    @staticmethod
    def __get_sca_related_summary_lines(detection: 'Detection') -> list[str]:
        return [f'{label}: [cyan]{value}[/]\n' for label, value in get_sca_policy_details(detection)]

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
