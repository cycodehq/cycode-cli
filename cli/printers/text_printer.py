import click
import math
from typing import List, Optional
from cli.printers.base_printer import BasePrinter
from cli.models import DocumentDetections, Detection, Document
from cli.config import config
from cli.consts import SECRET_SCAN_TYPE, COMMIT_RANGE_BASED_COMMAND_SCAN_TYPES
from cli.utils.string_utils import obfuscate_text


class TextPrinter(BasePrinter):
    RED_COLOR_NAME = 'red'
    WHITE_COLOR_NAME = 'white'
    GREEN_COLOR_NAME = 'green'

    scan_id: str
    scan_type: str
    command_scan_type: str
    show_secret: bool = False

    def __init__(self, context: click.Context):
        super().__init__(context)
        self.scan_id = context.obj.get('scan_id')
        self.scan_type = context.obj.get('scan_type')
        self.command_scan_type = context.info_name
        self.show_secret = context.obj.get('show_secret', False)

    def print_results(self, results: List[DocumentDetections]):
        click.secho(f"Scan Results: (scan_id: {self.scan_id})")

        if not results:
            click.secho("Good job! No issues were found!!! 👏👏👏", fg=self.GREEN_COLOR_NAME)
            return

        for document_detections in results:
            self._print_document_detections(document_detections)

        if self.context.obj.get('report_url'):
            click.secho(f"Report URL: {self.context.obj.get('report_url')}")

    def _print_document_detections(self, document_detections: DocumentDetections):
        document = document_detections.document
        lines_to_display = self._get_lines_to_display_count()
        for detection in document_detections.detections:
            self._print_detection_summary(detection, document.path)
            self._print_detection_code_segment(detection, document, lines_to_display)

    def _print_detection_summary(self, detection: Detection, document_path: str):
        detection_name = detection.type if self.scan_type == SECRET_SCAN_TYPE else detection.message
        detection_sha = detection.detection_details.get('sha512')
        detection_sha_message = f'\nSecret SHA: {detection_sha}' if detection_sha else ''
        detection_commit_id = detection.detection_details.get('commit_id')
        detection_commit_id_message = f'\nCommit SHA: {detection_commit_id}' if detection_commit_id else ''
        click.echo(
            f'⛔  Found issue of type: {click.style(detection_name, fg="bright_red", bold=True)} ' +
            f'(rule ID: {detection.detection_rule_id}) in file: {click.format_filename(document_path)} ' +
            f'{detection_sha_message}{detection_commit_id_message}  ⛔ ')

    def _print_detection_code_segment(self, detection: Detection, document: Document, code_segment_size: int):
        if self._is_git_diff_based_scan():
            self._print_detection_from_git_diff(detection, document)
            return

        self._print_detection_from_file(detection, document, code_segment_size)

    def _get_code_segment_start_line(self, detection_line: int, code_segment_size: int):
        start_line = detection_line - math.ceil(code_segment_size / 2)
        return 0 if start_line < 0 else start_line

    def _print_line_of_code_segment(self, document: Document, line: str, line_number: int,
                                    detection_position_in_line: int, violation_length: int, is_detection_line: bool):
        if is_detection_line:
            self._print_detection_line(document, line, line_number, detection_position_in_line, violation_length)
        else:
            self._print_line(document, line, line_number)

    def _print_detection_line(self, document: Document, line: str, line_number: int, detection_position_in_line: int,
                              violation_length: int):
        click.echo(
            f'{self._get_line_number_style(line_number)} '
            f'{self._get_detection_line_style(line, document.is_git_diff_format, detection_position_in_line, violation_length)}')

    def _print_line(self, document: Document, line: str, line_number: int):
        click.echo(
            f'{self._get_line_number_style(line_number)} {self._get_line_style(line, document.is_git_diff_format)}')

    def _get_detection_line_style(self, line: str, is_git_diff: bool, start_position: int, length: int):
        line_color = self._get_line_color(line, is_git_diff)
        if self.scan_type != SECRET_SCAN_TYPE or start_position < 0 or length < 0:
            return self._get_line_style(line, is_git_diff, line_color)

        violation = line[start_position: start_position + length]
        if not self.show_secret:
            violation = obfuscate_text(violation)
        line_to_violation = line[0: start_position]
        line_from_violation = line[start_position + length:]
        return f'{self._get_line_style(line_to_violation, is_git_diff, line_color)}' \
               f'{self._get_line_style(violation, is_git_diff, line_color, underline=True)}' \
               f'{self._get_line_style(line_from_violation, is_git_diff, line_color)}'

    def _get_line_style(self, line: str, is_git_diff: bool, color: Optional[str] = None, underline: bool = False):
        color = color or self._get_line_color(line, is_git_diff)
        return click.style(line, fg=color, bold=False, underline=underline)

    def _get_line_color(self, line: str, is_git_diff: bool):
        if not is_git_diff:
            return self.WHITE_COLOR_NAME

        if line.startswith('+'):
            return self.GREEN_COLOR_NAME

        if line.startswith('-'):
            return self.RED_COLOR_NAME

        return self.WHITE_COLOR_NAME

    def _get_position_in_line(self, text: str, position: int) -> int:
        return position - text.rfind('\n', 0, position) - 1

    def _get_line_number_style(self, line_number: int):
        return f'{click.style(str(line_number), fg=self.WHITE_COLOR_NAME, bold=False)} {click.style("|", fg=self.RED_COLOR_NAME, bold=False)}'

    def _get_lines_to_display_count(self) -> int:
        result_printer_configuration = config.get('result_printer')
        lines_to_display_of_scan = result_printer_configuration.get(self.scan_type, {}) \
            .get(self.command_scan_type, {}).get('lines_to_display')
        if lines_to_display_of_scan:
            return lines_to_display_of_scan

        return result_printer_configuration.get('default').get('lines_to_display')

    def _print_detection_from_file(self, detection: Detection, document: Document, code_segment_size: int):
        detection_details = detection.detection_details
        detection_line = detection_details.get('line', -1) if self.scan_type == SECRET_SCAN_TYPE else \
            detection_details.get('line_in_file', -1)
        detection_position = detection_details.get('start_position', -1)
        violation_length = detection_details.get('length', -1)

        file_content = document.content
        file_lines = file_content.splitlines()
        start_line = self._get_code_segment_start_line(detection_line, code_segment_size)
        detection_position_in_line = self._get_position_in_line(file_content, detection_position)

        click.echo()
        for i in range(code_segment_size):
            current_line_index = start_line + i
            if current_line_index >= len(file_lines):
                break

            current_line = file_lines[current_line_index]
            is_detection_line = current_line_index == detection_line
            self._print_line_of_code_segment(document, current_line, current_line_index + 1, detection_position_in_line,
                                             violation_length, is_detection_line)
        click.echo()

    def _print_detection_from_git_diff(self, detection: Detection, document: Document):
        detection_details = detection.detection_details
        detection_line_number = detection_details.get('line', -1)
        detection_line_number_in_original_file = detection_details.get('line_in_file', -1)
        detection_position = detection_details.get('start_position', -1)
        violation_length = detection_details.get('length', -1)

        git_diff_content = document.content
        git_diff_lines = git_diff_content.splitlines()
        detection_line = git_diff_lines[detection_line_number]
        detection_position_in_line = self._get_position_in_line(git_diff_content, detection_position)

        click.echo()
        self._print_detection_line(document, detection_line, detection_line_number_in_original_file,
                                   detection_position_in_line, violation_length)
        click.echo()

    def _is_git_diff_based_scan(self):
        return self.command_scan_type in COMMIT_RANGE_BASED_COMMAND_SCAN_TYPES and self.scan_type == SECRET_SCAN_TYPE
