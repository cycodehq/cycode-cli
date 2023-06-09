from typing import List, NamedTuple

import click
from texttable import Texttable

from cycode.cli.printers.text_printer import TextPrinter
from cycode.cli.utils.string_utils import obfuscate_text, get_position_in_line
from cycode.cli.consts import SECRET_SCAN_TYPE, SAST_SCAN_TYPE, INFRA_CONFIGURATION_SCAN_TYPE
from cycode.cli.models import DocumentDetections, Detection, CliError, CliResult, Document
from cycode.cli.printers.base_printer import BasePrinter


class ColumnInfo(NamedTuple):
    name: str
    width_secret: int = 1
    width_sast: int = 1
    width_iac: int = 1


VIOLATION_COLUMN = ColumnInfo(name='Violation', width_secret=2)
SECRET_SHA_COLUMN = ColumnInfo(name='Secret SHA', width_secret=2)
COMMIT_SHA_COLUMN = ColumnInfo(name='Commit SHA')
VIOLATION_LENGTH_COLUMN = ColumnInfo(name='Violation Length')

DETECTIONS_COMMON_HEADERS = [
    ColumnInfo(name='Issue Type', width_secret=2, width_iac=4, width_sast=7),
    ColumnInfo(name='Rule ID', width_secret=2, width_iac=3, width_sast=2),
    ColumnInfo(name='File Path', width_secret=2, width_iac=3, width_sast=3),
    ColumnInfo(name='Line Number'),
    ColumnInfo(name='Column Number'),
]


class TablePrinter(BasePrinter):
    def __init__(self, context: click.Context):
        super().__init__(context)
        self.context = context
        self.scan_id: str = context.obj.get('scan_id')
        self.scan_type: str = context.obj.get('scan_type')
        self.show_secret: bool = context.obj.get('show_secret', False)

    def print_result(self, result: CliResult) -> None:
        TextPrinter(self.context).print_result(result)

    def print_error(self, error: CliError) -> None:
        TextPrinter(self.context).print_error(error)

    def print_scan_results(self, results: List[DocumentDetections]):
        click.secho(f'Scan Results: (scan_id: {self.scan_id})')

        if not results:
            click.secho('Good job! No issues were found!!! 👏👏👏', fg=self.GREEN_COLOR_NAME)
            return

        self._print_results(results)

        report_url = self.context.obj.get('report_url')
        if report_url:
            click.secho(f'Report URL: {report_url}')

    def _print_results(self, results: List[DocumentDetections]) -> None:
        headers = self._get_table_headers()

        rows = []
        for detections in results:
            for detection in detections.detections:
                rows.append(self._get_detection_row(detection, detections.document))

        if rows:
            self._print_table(headers, rows)

    def _print_table(self, headers: List[ColumnInfo], rows: List[List[str]]) -> None:
        text_table = Texttable()
        text_table.header([header.name for header in headers])
        text_table.set_cols_width(self._get_table_columns_width(headers))

        for row in rows:
            text_table.add_row(row)

        click.echo(text_table.draw())

    def _is_git_repository(self) -> bool:
        return self.context.obj.get('remote_url') is not None

    def _get_table_headers(self) -> list:
        headers = DETECTIONS_COMMON_HEADERS.copy()

        if self._is_git_repository():
            headers.insert(3, COMMIT_SHA_COLUMN)

        if self.scan_type == SECRET_SCAN_TYPE:
            headers.insert(3, SECRET_SHA_COLUMN)
            headers.append(VIOLATION_LENGTH_COLUMN)
            headers.append(VIOLATION_COLUMN)

        return headers

    def _get_table_columns_width(self, headers: List[ColumnInfo]) -> List[int]:
        header_width_size_cols = []
        for header in headers:
            width_multiplier = 1
            if self.scan_type == SECRET_SCAN_TYPE:
                width_multiplier = header.width_secret
            elif self.scan_type == INFRA_CONFIGURATION_SCAN_TYPE:
                width_multiplier = header.width_iac
            elif self.scan_type == SAST_SCAN_TYPE:
                width_multiplier = header.width_sast

            header_width_size_cols.append(len(header.name) * width_multiplier)

        return header_width_size_cols

    def _get_detection_row(self, detection: Detection, document: Document) -> List[str]:
        return [
            *self._get_detection_summary_fields(detection, document.path),
            *self._get_detection_code_segment_fields(detection, document),
        ]

    def _get_detection_summary_fields(self, detection: Detection, document_path: str) -> List[str]:
        issue_type = detection.message
        if self.scan_type == SECRET_SCAN_TYPE:
            issue_type = detection.type

        rows = [
            issue_type,
            detection.detection_rule_id,
            click.format_filename(document_path),
        ]

        if self.scan_type == SECRET_SCAN_TYPE:
            rows.append(detection.detection_details.get('sha512', ''))

        if self._is_git_repository():
            rows.append(detection.detection_details.get('commit_id', ''))

        return rows

    def _get_detection_code_segment_fields(self, detection: Detection, document: Document) -> List[str]:
        detection_details = detection.detection_details

        detection_line = detection_details.get('line_in_file', -1)
        if self.scan_type == SECRET_SCAN_TYPE:
            detection_line = detection_details.get('line', -1)

        detection_position = get_position_in_line(document.content, detection_details.get('start_position', -1))
        violation_length = detection_details.get('length', -1)

        rows = [
            detection_line,
            detection_position,
        ]

        if self.scan_type == SECRET_SCAN_TYPE:
            rows.append(f'{violation_length} chars')

            violation = ''

            file_content_lines = document.content.splitlines()
            if detection_line < len(file_content_lines):
                line = file_content_lines[detection_line]
                violation = line[detection_position: detection_position + violation_length]

            if not self.show_secret:
                violation = obfuscate_text(violation)

            rows.append(violation)

        return rows
