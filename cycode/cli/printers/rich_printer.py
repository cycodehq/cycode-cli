from typing import TYPE_CHECKING, Optional

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cycode.cli import consts
from cycode.cli.cli_types import SeverityOption
from cycode.cli.printers.text_printer import TextPrinter
from cycode.cli.printers.utils.code_snippet_syntax import get_code_snippet_syntax
from cycode.cli.printers.utils.detection_data import (
    get_detection_clickable_cwe_cve,
    get_detection_file_path,
    get_detection_title,
)
from cycode.cli.printers.utils.detection_ordering.common_ordering import sort_and_group_detections_from_scan_result
from cycode.cli.printers.utils.rich_helpers import get_columns_in_1_to_3_ratio, get_markdown_panel, get_panel

if TYPE_CHECKING:
    from cycode.cli.models import CliError, Detection, Document, LocalScanResult


class RichPrinter(TextPrinter):
    MAX_PATH_LENGTH = 60

    def print_scan_results(
        self, local_scan_results: list['LocalScanResult'], errors: Optional[dict[str, 'CliError']] = None
    ) -> None:
        if not errors and all(result.issue_detected == 0 for result in local_scan_results):
            self.console.print(self.NO_DETECTIONS_MESSAGE)
            return

        detections, _ = sort_and_group_detections_from_scan_result(local_scan_results)
        detections_count = len(detections)
        for detection_number, (detection, document) in enumerate(detections, start=1):
            self._print_violation_card(
                document,
                detection,
                detection_number,
                detections_count,
            )

        self.print_scan_results_summary(local_scan_results)
        self.print_report_urls_and_errors(local_scan_results, errors)

    def _get_details_table(self, detection: 'Detection') -> Table:
        details_table = Table(show_header=False, box=None, padding=(0, 1))

        details_table.add_column('Key', style='dim')
        details_table.add_column('Value', style='', overflow='fold')

        severity = detection.severity if detection.severity else 'N/A'
        severity_icon = SeverityOption.get_member_emoji(severity.lower())
        details_table.add_row('Severity', f'{severity_icon} {SeverityOption(severity).__rich__()}')

        path = str(get_detection_file_path(self.scan_type, detection))
        shorten_path = f'...{path[-self.MAX_PATH_LENGTH :]}' if len(path) > self.MAX_PATH_LENGTH else path
        details_table.add_row('In file', f'[link=file://{path}]{shorten_path}[/]')

        self._add_scan_related_rows(details_table, detection)

        details_table.add_row('Rule ID', detection.detection_rule_id)

        return details_table

    def _add_scan_related_rows(self, details_table: Table, detection: 'Detection') -> None:
        scan_type_details_handlers = {
            consts.SECRET_SCAN_TYPE: self.__add_secret_scan_related_rows,
            consts.SCA_SCAN_TYPE: self.__add_sca_scan_related_rows,
            consts.IAC_SCAN_TYPE: self.__add_iac_scan_related_rows,
            consts.SAST_SCAN_TYPE: self.__add_sast_scan_related_rows,
        }

        if self.scan_type not in scan_type_details_handlers:
            raise ValueError(f'Unknown scan type: {self.scan_type}')

        scan_enricher_function = scan_type_details_handlers[self.scan_type]
        scan_enricher_function(details_table, detection)

    @staticmethod
    def __add_secret_scan_related_rows(details_table: Table, detection: 'Detection') -> None:
        details_table.add_row('Secret SHA', detection.detection_details.get('sha512'))

    @staticmethod
    def __add_sca_scan_related_rows(details_table: Table, detection: 'Detection') -> None:
        detection_details = detection.detection_details

        details_table.add_row('CVEs', get_detection_clickable_cwe_cve(consts.SCA_SCAN_TYPE, detection))
        details_table.add_row('Package', detection_details.get('package_name'))
        details_table.add_row('Version', detection_details.get('package_version'))

        if detection.has_alert:
            patched_version = detection_details['alert'].get('first_patched_version')
            details_table.add_row('First patched version', patched_version or 'Not fixed')

        dependency_path = detection_details.get('dependency_paths')
        details_table.add_row('Dependency path', dependency_path or 'N/A')

        if not detection.has_alert:
            details_table.add_row('License', detection_details.get('license'))

    @staticmethod
    def __add_iac_scan_related_rows(details_table: Table, detection: 'Detection') -> None:
        details_table.add_row('IaC Provider', detection.detection_details.get('infra_provider'))

    @staticmethod
    def __add_sast_scan_related_rows(details_table: Table, detection: 'Detection') -> None:
        details_table.add_row('CWE', get_detection_clickable_cwe_cve(consts.SAST_SCAN_TYPE, detection))
        details_table.add_row('Subcategory', detection.detection_details.get('category'))
        details_table.add_row('Language', ', '.join(detection.detection_details.get('languages', [])))

        engine_id_to_display_name = {
            '5db84696-88dc-11ec-a8a3-0242ac120002': 'Semgrep OSS (Orchestrated by Cycode)',
            '560a0abd-d7da-4e6d-a3f1-0ed74895295c': 'Bearer (Powered by Cycode)',
        }
        engine_id = detection.detection_details.get('external_scanner_id')
        details_table.add_row('Security Tool', engine_id_to_display_name.get(engine_id, 'N/A'))

    def _print_violation_card(
        self, document: 'Document', detection: 'Detection', detection_number: int, detections_count: int
    ) -> None:
        details_table = self._get_details_table(detection)
        details_panel = get_panel(
            details_table,
            title=':mag: Details',
        )

        code_snippet_panel = get_panel(
            get_code_snippet_syntax(
                self.scan_type,
                self.command_scan_type,
                detection,
                document,
                obfuscate=not self.show_secret,
                lines_to_display_before=3,
                lines_to_display_after=3,
            ),
            title=':computer: Code Snippet',
        )

        if detection.has_alert:
            summary = detection.detection_details['alert'].get('description')
        else:
            summary = detection.detection_details.get('description') or detection.message

        summary_panel = None
        if summary:
            summary_panel = get_markdown_panel(
                summary,
                title=':memo: Summary',
            )

        custom_guidelines_panel = None
        custom_guidelines = detection.detection_details.get('custom_remediation_guidelines')
        if custom_guidelines:
            custom_guidelines_panel = get_markdown_panel(
                custom_guidelines,
                title=':office: Company Guidelines',
            )

        navigation = Text(f'Violation {detection_number} of {detections_count}', style='dim', justify='right')

        renderables = [navigation, get_columns_in_1_to_3_ratio(details_panel, code_snippet_panel)]
        if summary_panel:
            renderables.append(summary_panel)
        if custom_guidelines_panel:
            renderables.append(custom_guidelines_panel)

        violation_card_panel = Panel(
            Group(*renderables),
            title=get_detection_title(self.scan_type, detection),
            border_style=SeverityOption.get_member_color(detection.severity),
            title_align='center',
        )

        self.console.print(violation_card_panel)
