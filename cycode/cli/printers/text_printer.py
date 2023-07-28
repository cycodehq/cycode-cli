import math
from typing import TYPE_CHECKING, Dict, List, Optional

import click

from cycode.cli.config import config
from cycode.cli.consts import COMMIT_RANGE_BASED_COMMAND_SCAN_TYPES, SECRET_SCAN_TYPE
from cycode.cli.models import CliError, CliResult, Detection, Document, DocumentDetections
from cycode.cli.printers.printer_base import PrinterBase
from cycode.cli.utils.string_utils import get_position_in_line, obfuscate_text

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult


class TextPrinter(PrinterBase):
    def __init__(self, context: click.Context) -> None:
        super().__init__(context)
        self.scan_type: str = context.obj.get('scan_type')
        self.command_scan_type: str = context.info_name
        self.show_secret: bool = context.obj.get('show_secret', False)

    def print_result(self, result: CliResult) -> None:
        color = None
        if not result.success:
            color = self.RED_COLOR_NAME

        click.secho(result.message, fg=color)

    def print_error(self, error: CliError) -> None:
        click.secho(error.message, fg=self.RED_COLOR_NAME)

    def print_scan_results(
        self, local_scan_results: List['LocalScanResult'], errors: Optional[Dict[str, 'CliError']] = None
    ) -> None:
        if not errors and all(result.issue_detected == 0 for result in local_scan_results):
            click.secho('Good job! No issues were found!!! 👏👏👏', fg=self.GREEN_COLOR_NAME)
            return

        for local_scan_result in local_scan_results:
            for document_detections in local_scan_result.document_detections:
                self._print_document_detections(
                    document_detections, local_scan_result.scan_id, local_scan_result.report_url
                )

        if not errors:
            return

        click.secho(
            'Unfortunately, Cycode was unable to complete the full scan. '
            'Please note that not all results may be available:',
            fg='red',
        )
        for scan_id, error in errors.items():
            click.echo(f'- {scan_id}: ', nl=False)
            self.print_error(error)

    def _print_document_detections(
        self, document_detections: DocumentDetections, scan_id: str, report_url: Optional[str]
    ) -> None:
        document = document_detections.document
        lines_to_display = self._get_lines_to_display_count()
        for detection in document_detections.detections:
            self._print_detection_summary(detection, document.path, scan_id, report_url)
            self._print_detection_code_segment(detection, document, lines_to_display)

    def _print_detection_summary(
        self, detection: Detection, document_path: str, scan_id: str, report_url: Optional[str]
    ) -> None:
        detection_name = detection.type if self.scan_type == SECRET_SCAN_TYPE else detection.message

        detection_sha = detection.detection_details.get('sha512')
        detection_sha_message = f'\nSecret SHA: {detection_sha}' if detection_sha else ''

        scan_id_message = f'\nScan ID: {scan_id}'
        report_url_message = f'\nReport URL: {report_url}' if report_url else ''

        detection_commit_id = detection.detection_details.get('commit_id')
        detection_commit_id_message = f'\nCommit SHA: {detection_commit_id}' if detection_commit_id else ''

        click.echo(
            f'⛔  Found issue of type: {click.style(detection_name, fg="bright_red", bold=True)} '
            f'(rule ID: {detection.detection_rule_id}) in file: {click.format_filename(document_path)} '
            f'{detection_sha_message}{scan_id_message}{report_url_message}{detection_commit_id_message}  ⛔'
        )

    def _print_detection_code_segment(self, detection: Detection, document: Document, code_segment_size: int) -> None:
        if self._is_git_diff_based_scan():
            self._print_detection_from_git_diff(detection, document)
            return

        self._print_detection_from_file(detection, document, code_segment_size)

    @staticmethod
    def _get_code_segment_start_line(detection_line: int, code_segment_size: int) -> int:
        start_line = detection_line - math.ceil(code_segment_size / 2)
        return 0 if start_line < 0 else start_line

    def _print_line_of_code_segment(
        self,
        document: Document,
        line: str,
        line_number: int,
        detection_position_in_line: int,
        violation_length: int,
        is_detection_line: bool,
    ) -> None:
        if is_detection_line:
            self._print_detection_line(document, line, line_number, detection_position_in_line, violation_length)
        else:
            self._print_line(document, line, line_number)

    def _print_detection_line(
        self, document: Document, line: str, line_number: int, detection_position_in_line: int, violation_length: int
    ) -> None:
        detection_line = self._get_detection_line_style(
            line, document.is_git_diff_format, detection_position_in_line, violation_length
        )

        click.echo(f'{self._get_line_number_style(line_number)} {detection_line}')

    def _print_line(self, document: Document, line: str, line_number: int) -> None:
        line_no = self._get_line_number_style(line_number)
        line = self._get_line_style(line, document.is_git_diff_format)

        click.echo(f'{line_no} {line}')

    def _get_detection_line_style(self, line: str, is_git_diff: bool, start_position: int, length: int) -> str:
        line_color = self._get_line_color(line, is_git_diff)
        if self.scan_type != SECRET_SCAN_TYPE or start_position < 0 or length < 0:
            return self._get_line_style(line, is_git_diff, line_color)

        violation = line[start_position : start_position + length]
        if not self.show_secret:
            violation = obfuscate_text(violation)

        line_to_violation = line[0:start_position]
        line_from_violation = line[start_position + length :]

        return (
            f'{self._get_line_style(line_to_violation, is_git_diff, line_color)}'
            f'{self._get_line_style(violation, is_git_diff, line_color, underline=True)}'
            f'{self._get_line_style(line_from_violation, is_git_diff, line_color)}'
        )

    def _get_line_style(
        self, line: str, is_git_diff: bool, color: Optional[str] = None, underline: bool = False
    ) -> str:
        if color is None:
            color = self._get_line_color(line, is_git_diff)

        return click.style(line, fg=color, bold=False, underline=underline)

    def _get_line_color(self, line: str, is_git_diff: bool) -> str:
        if not is_git_diff:
            return self.WHITE_COLOR_NAME

        if line.startswith('+'):
            return self.GREEN_COLOR_NAME

        if line.startswith('-'):
            return self.RED_COLOR_NAME

        return self.WHITE_COLOR_NAME

    def _get_line_number_style(self, line_number: int) -> str:
        return (
            f'{click.style(str(line_number), fg=self.WHITE_COLOR_NAME, bold=False)} '
            f'{click.style("|", fg=self.RED_COLOR_NAME, bold=False)}'
        )

    def _get_lines_to_display_count(self) -> int:
        result_printer_configuration = config.get('result_printer')
        lines_to_display_of_scan = (
            result_printer_configuration.get(self.scan_type, {}).get(self.command_scan_type, {}).get('lines_to_display')
        )
        if lines_to_display_of_scan:
            return lines_to_display_of_scan

        return result_printer_configuration.get('default').get('lines_to_display')

    def _print_detection_from_file(self, detection: Detection, document: Document, code_segment_size: int) -> None:
        detection_details = detection.detection_details
        detection_line = (
            detection_details.get('line', -1)
            if self.scan_type == SECRET_SCAN_TYPE
            else detection_details.get('line_in_file', -1)
        )
        detection_position = detection_details.get('start_position', -1)
        violation_length = detection_details.get('length', -1)

        file_content = document.content
        file_lines = file_content.splitlines()
        start_line = self._get_code_segment_start_line(detection_line, code_segment_size)
        detection_position_in_line = get_position_in_line(file_content, detection_position)

        click.echo()
        for i in range(code_segment_size):
            current_line_index = start_line + i
            if current_line_index >= len(file_lines):
                break

            current_line = file_lines[current_line_index]
            is_detection_line = current_line_index == detection_line
            self._print_line_of_code_segment(
                document,
                current_line,
                current_line_index + 1,
                detection_position_in_line,
                violation_length,
                is_detection_line,
            )
        click.echo()

    def _print_detection_from_git_diff(self, detection: Detection, document: Document) -> None:
        detection_details = detection.detection_details
        detection_line_number = detection_details.get('line', -1)
        detection_line_number_in_original_file = detection_details.get('line_in_file', -1)
        detection_position = detection_details.get('start_position', -1)
        violation_length = detection_details.get('length', -1)

        git_diff_content = document.content
        git_diff_lines = git_diff_content.splitlines()
        detection_line = git_diff_lines[detection_line_number]
        detection_position_in_line = get_position_in_line(git_diff_content, detection_position)

        click.echo()
        self._print_detection_line(
            document,
            detection_line,
            detection_line_number_in_original_file,
            detection_position_in_line,
            violation_length,
        )
        click.echo()

    def _is_git_diff_based_scan(self) -> bool:
        return self.command_scan_type in COMMIT_RANGE_BASED_COMMAND_SCAN_TYPES and self.scan_type == SECRET_SCAN_TYPE
