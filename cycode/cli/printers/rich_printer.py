from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cycode.cli import consts
from cycode.cli.cli_types import SeverityOption
from cycode.cli.printers.text_printer import TextPrinter
from cycode.cli.printers.utils.code_snippet_syntax import get_code_snippet_syntax
from cycode.cli.printers.utils.detection_data import get_detection_title
from cycode.cli.printers.utils.detection_ordering.common_ordering import sort_and_group_detections_from_scan_result
from cycode.cli.printers.utils.rich_helpers import get_columns_in_1_to_3_ratio, get_markdown_panel, get_panel

if TYPE_CHECKING:
    from cycode.cli.models import CliError, Detection, Document, LocalScanResult


class RichPrinter(TextPrinter):
    def print_scan_results(
        self, local_scan_results: List['LocalScanResult'], errors: Optional[Dict[str, 'CliError']] = None
    ) -> None:
        if not errors and all(result.issue_detected == 0 for result in local_scan_results):
            self.console.print(self.NO_DETECTIONS_MESSAGE)
            return

        current_file = None
        detections, _ = sort_and_group_detections_from_scan_result(local_scan_results)
        detections_count = len(detections)
        for detection_number, (detection, document) in enumerate(detections, start=1):
            if current_file != document.path:
                current_file = document.path
                self._print_file_header(current_file)

            self._print_violation_card(
                document,
                detection,
                detection_number,
                detections_count,
            )

        self.print_report_urls_and_errors(local_scan_results, errors)

    def _print_file_header(self, file_path: str) -> None:
        clickable_path = f'[link=file://{file_path}]{file_path}[/link]'
        file_header = Panel(
            Text.from_markup(f'[b purple3]:file_folder: File: {clickable_path}[/]', justify='center'),
            border_style='dim',
        )
        self.console.print(file_header)

    def _get_details_table(self, detection: 'Detection') -> Table:
        details_table = Table(show_header=False, box=None, padding=(0, 1))

        details_table.add_column('Key', style='dim')
        details_table.add_column('Value', style='', overflow='fold')

        severity = detection.severity if detection.severity else 'N/A'
        severity_icon = SeverityOption.get_member_emoji(severity.lower())
        details_table.add_row('Severity', f'{severity_icon} {SeverityOption(severity).__rich__()}')

        detection_details = detection.detection_details
        path = Path(detection_details.get('file_name', ''))
        details_table.add_row('In file', path.name)  # it is name already except for IaC :)

        # we do not allow using rich output with SCA; SCA designed to be used with table output
        if self.scan_type == consts.IAC_SCAN_TYPE:
            details_table.add_row('IaC Provider', detection_details.get('infra_provider'))
        elif self.scan_type == consts.SECRET_SCAN_TYPE:
            details_table.add_row('Secret SHA', detection_details.get('sha512'))
        elif self.scan_type == consts.SAST_SCAN_TYPE:
            details_table.add_row('Subcategory', detection_details.get('category'))
            details_table.add_row('Language', ', '.join(detection_details.get('languages', [])))

            engine_id_to_display_name = {
                '5db84696-88dc-11ec-a8a3-0242ac120002': 'Semgrep OSS (Orchestrated by Cycode)',
                '560a0abd-d7da-4e6d-a3f1-0ed74895295c': 'Bearer (Powered by Cycode)',
            }
            engine_id = detection.detection_details.get('external_scanner_id')
            details_table.add_row('Security Tool', engine_id_to_display_name.get(engine_id, 'N/A'))

        details_table.add_row('Rule ID', detection.detection_rule_id)

        return details_table

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
            ),
            title=':computer: Code Snippet',
        )

        guidelines_panel = None
        guidelines = detection.detection_details.get('remediation_guidelines')
        if guidelines:
            guidelines_panel = get_markdown_panel(
                guidelines,
                title=':clipboard: Cycode Guidelines',
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
        if guidelines_panel:
            renderables.append(guidelines_panel)
        if custom_guidelines_panel:
            renderables.append(custom_guidelines_panel)

        violation_card_panel = Panel(
            Group(*renderables),
            title=get_detection_title(self.scan_type, detection),
            border_style=SeverityOption.get_member_color(detection.severity),
            title_align='center',
        )

        self.console.print(violation_card_panel)
