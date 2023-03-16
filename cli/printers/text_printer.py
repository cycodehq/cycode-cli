import math
from typing import List, Optional, Dict

import click
from texttable import Texttable

from cli.config import config
from cli.consts import SECRET_SCAN_TYPE, COMMIT_RANGE_BASED_COMMAND_SCAN_TYPES, LICENSE_COMPLIANCE_POLICY_ID, \
    PACKAGE_VULNERABILITY_POLICY_ID, PREVIEW_DETECTIONS_COMMON_HEADERS
from cli.models import DocumentDetections, Detection, Document
from cli.printers.base_printer import BasePrinter
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
        self.special_print_per_detection_type_id = [LICENSE_COMPLIANCE_POLICY_ID, PACKAGE_VULNERABILITY_POLICY_ID]

    def print_results(self, results: List[DocumentDetections]):
        click.secho(f"Scan Results: (scan_id: {self.scan_id})")

        if not results:
            click.secho("Good job! No issues were found!!! 👏👏👏", fg=self.GREEN_COLOR_NAME)
            return

        for document_detections in results:
            self._print_document_detections(document_detections)

        detections_per_detection_type_id = self._extract_detections_per_detection_type_id(results)

        self._print_detection_per_detection_type_id(detections_per_detection_type_id)

        if self.context.obj.get('report_url'):
            click.secho(f"Report URL: {self.context.obj.get('report_url')}")

    def _print_document_detections(self, document_detections: DocumentDetections):
        document = document_detections.document
        lines_to_display = self._get_lines_to_display_count()
        for detection in document_detections.detections:
            if detection.detection_type_id not in self.special_print_per_detection_type_id:
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

    def _extract_detections_per_detection_type_id(self, results: List[DocumentDetections]):
        detections_per_detection_type_id = {}
        for detection_type_id in self.special_print_per_detection_type_id:
            detections_per_detection_type_id[detection_type_id] = []

        for document_detection in results:
            for detection in document_detection.detections:
                if detection.detection_type_id in self.special_print_per_detection_type_id:
                    detections_per_detection_type_id[detection.detection_type_id].append(detection)

        return detections_per_detection_type_id

    def _print_detection_per_detection_type_id(self, detections_per_detection_type_id: Dict[str, Detection]):
        text_table = Texttable()

        for detection_type_id in list(detections_per_detection_type_id):
            text_table.reset()
            if detection_type_id == PACKAGE_VULNERABILITY_POLICY_ID:
                self._print_table_detections(text_table,
                                             detections_per_detection_type_id[detection_type_id],
                                             'Upgrade',
                                             self._get_upgrade_package_vulnerability,
                                             "Dependencies Vulnerabilities")
            if detection_type_id == LICENSE_COMPLIANCE_POLICY_ID:
                self._print_table_detections(text_table,
                                             detections_per_detection_type_id[detection_type_id],
                                             'License',
                                             self._get_license,
                                             "License Compliance")

    def _print_table_detections(self, text_table: Texttable, detections: List[Detection], additional_column: str,
                                additional_value_callback, title: str):
        if len(detections) > 0:
            self._print_summary_issues(detections, title)
            headers = PREVIEW_DETECTIONS_COMMON_HEADERS[:]
            headers.append(additional_column)
            text_table.header(headers)
            header_width_size_cols = []
            for header in headers:
                header_width_size_cols.append(len(header))
            text_table.set_cols_width(header_width_size_cols)
            for detection in detections:

                row = self._get_common_detection_fields(detection)
                row.append(additional_value_callback(detection))
                text_table.add_row(row)
            click.echo(text_table.draw())

    def _print_summary_issues(self, detections: List, title: str):
        click.echo(
            f'⛔ Found {len(detections)} issues of type: {click.style(title, bold=True)}')

    def _get_common_detection_fields(self, detection: Detection):
        return [
            detection.detection_details.get('advisory_severity'),
            detection.detection_details.get('repository_name'),
            detection.detection_details.get('file_name'),
            detection.detection_details.get('ecosystem'),
            detection.detection_details.get('package_name'),
            detection.detection_details.get('is_direct_dependency_str'),
            detection.detection_details.get('is_dev_dependency_str')
        ]

    def _get_upgrade_package_vulnerability(self, detection: Detection):
        alert = detection.detection_details.get('alert')
        return f'{alert.get("vulnerable_requirements")} -> {alert.get("first_patched_version")}'

    def _get_license(self, detection: Detection):
        return f'{detection.detection_details.get("license")}'
