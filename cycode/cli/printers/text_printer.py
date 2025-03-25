import math
import urllib.parse
from typing import TYPE_CHECKING, Dict, List, Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.syntax import Syntax

from cycode.cli.cli_types import SeverityOption
from cycode.cli.consts import COMMIT_RANGE_BASED_COMMAND_SCAN_TYPES, SECRET_SCAN_TYPE
from cycode.cli.models import CliError, CliResult, Detection, Document, DocumentDetections
from cycode.cli.printers.printer_base import PrinterBase
from cycode.cli.utils.string_utils import get_position_in_line, obfuscate_text

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult


class TextPrinter(PrinterBase):
    def __init__(self, ctx: typer.Context) -> None:
        super().__init__(ctx)
        self.scan_type = ctx.obj.get('scan_type')
        self.command_scan_type: str = ctx.info_name
        self.show_secret: bool = ctx.obj.get('show_secret', False)

    def print_result(self, result: CliResult) -> None:
        color = None
        if not result.success:
            color = self.RED_COLOR_NAME

        typer.secho(result.message, fg=color)

        if not result.data:
            return

        typer.secho('\nAdditional data:', fg=color)
        for name, value in result.data.items():
            typer.secho(f'- {name}: {value}', fg=color)

    def print_error(self, error: CliError) -> None:
        typer.secho(error.message, fg=self.RED_COLOR_NAME)

    def print_scan_results(
        self, local_scan_results: List['LocalScanResult'], errors: Optional[Dict[str, 'CliError']] = None
    ) -> None:
        if not errors and all(result.issue_detected == 0 for result in local_scan_results):
            typer.secho('Good job! No issues were found!!! 👏👏👏', fg=self.GREEN_COLOR_NAME)
            return

        for local_scan_result in local_scan_results:
            for document_detections in local_scan_result.document_detections:
                self._print_document_detections(document_detections)

        report_urls = [scan_result.report_url for scan_result in local_scan_results if scan_result.report_url]

        self._print_report_urls(report_urls, self.ctx.obj.get('aggregation_report_url'))
        if not errors:
            return

        typer.secho(
            'Unfortunately, Cycode was unable to complete the full scan. '
            'Please note that not all results may be available:',
            fg='red',
        )
        for scan_id, error in errors.items():
            typer.echo(f'- {scan_id}: ', nl=False)
            self.print_error(error)

    def _print_document_detections(self, document_detections: DocumentDetections) -> None:
        document = document_detections.document
        for detection in document_detections.detections:
            self._print_detection_summary(detection, document.path)
            self._print_new_line()
            self._print_detection_code_segment(detection, document)
            self._print_new_line()

    @staticmethod
    def _print_new_line() -> None:
        typer.echo()

    def _print_detection_summary(self, detection: Detection, document_path: str) -> None:
        detection_name = detection.type if self.scan_type == SECRET_SCAN_TYPE else detection.message

        detection_severity = detection.severity or 'N/A'
        detection_severity_color = SeverityOption.get_member_color(detection_severity)
        detection_severity = f'[{detection_severity_color}]{detection_severity.upper()}[/{detection_severity_color}]'

        escaped_document_path = escape(urllib.parse.quote(document_path))
        clickable_document_path = f'[link file://{escaped_document_path}]{document_path}'

        detection_commit_id = detection.detection_details.get('commit_id')
        detection_commit_id_message = f'\nCommit SHA: {detection_commit_id}' if detection_commit_id else ''

        company_guidelines = detection.detection_details.get('custom_remediation_guidelines')
        company_guidelines_message = f'\nCompany Guideline: {company_guidelines}' if company_guidelines else ''

        Console().print(
            f':no_entry: '
            f'Found {detection_severity} issue of type: [bright_red][bold]{detection_name}[/bold][/bright_red] '
            f'in file: {clickable_document_path} '
            f'{detection_commit_id_message}'
            f'{company_guidelines_message}'
            f' :no_entry:',
            highlight=True,
        )

    def _print_detection_code_segment(
        self, detection: Detection, document: Document, lines_to_display: int = 3
    ) -> None:
        if self._is_git_diff_based_scan():
            # it will print just one line
            self._print_detection_from_git_diff(detection, document)
            return

        self._print_detection_from_file(detection, document, lines_to_display)

    @staticmethod
    def _print_report_urls(report_urls: List[str], aggregation_report_url: Optional[str] = None) -> None:
        if not report_urls and not aggregation_report_url:
            return
        if aggregation_report_url:
            typer.echo(f'Report URL: {aggregation_report_url}')
            return

        typer.echo('Report URLs:')
        for report_url in report_urls:
            typer.echo(f'- {report_url}')

    @staticmethod
    def _get_code_segment_start_line(detection_line: int, lines_to_display: int) -> int:
        start_line = detection_line - math.ceil(lines_to_display / 2)
        return 0 if start_line < 0 else start_line

    def _get_detection_line(self, detection: Detection) -> int:
        return (
            detection.detection_details.get('line', -1)
            if self.scan_type == SECRET_SCAN_TYPE
            else detection.detection_details.get('line_in_file', -1) - 1
        )

    def _print_detection_from_file(self, detection: Detection, document: Document, lines_to_display: int) -> None:
        detection_details = detection.detection_details
        detection_line = self._get_detection_line(detection)
        start_line_index = self._get_code_segment_start_line(detection_line, lines_to_display)
        detection_position = get_position_in_line(document.content, detection_details.get('start_position', -1))
        violation_length = detection_details.get('length', -1)

        code_lines_to_render = []
        document_content_lines = document.content.splitlines()
        for line_index in range(lines_to_display):
            current_line_index = start_line_index + line_index
            if current_line_index >= len(document_content_lines):
                break

            line_content = document_content_lines[current_line_index]

            line_with_detection = current_line_index == detection_line
            if self.scan_type == SECRET_SCAN_TYPE and line_with_detection and not self.show_secret:
                violation = line_content[detection_position : detection_position + violation_length]
                code_lines_to_render.append(line_content.replace(violation, obfuscate_text(violation)))
            else:
                code_lines_to_render.append(line_content)

        code_to_render = '\n'.join(code_lines_to_render)
        Console().print(
            Syntax(
                code=code_to_render,
                lexer=Syntax.guess_lexer(document.path, code=code_to_render),
                line_numbers=True,
                dedent=True,
                tab_size=2,
                start_line=start_line_index + 1,
                highlight_lines={
                    detection_line + 1,
                },
            )
        )

    def _print_detection_from_git_diff(self, detection: Detection, document: Document) -> None:
        detection_details = detection.detection_details
        detection_line = self._get_detection_line(detection)
        detection_position = detection_details.get('start_position', -1)
        violation_length = detection_details.get('length', -1)

        line_content = document.content.splitlines()[detection_line]
        detection_position_in_line = get_position_in_line(document.content, detection_position)
        if self.scan_type == SECRET_SCAN_TYPE and not self.show_secret:
            violation = line_content[detection_position_in_line : detection_position_in_line + violation_length]
            line_content = line_content.replace(violation, obfuscate_text(violation))

        Console().print(
            Syntax(
                line_content,
                lexer='diff',
                line_numbers=True,
                start_line=detection_line,
                dedent=True,
                tab_size=2,
                highlight_lines={detection_line + 1},
            )
        )

    def _is_git_diff_based_scan(self) -> bool:
        return self.command_scan_type in COMMIT_RANGE_BASED_COMMAND_SCAN_TYPES and self.scan_type == SECRET_SCAN_TYPE
