from typing import List

import click

from cycode.cli.printers.base_table_printer import BaseTablePrinter, ColumnInfo, Table
from cycode.cli.utils.string_utils import obfuscate_text, get_position_in_line
from cycode.cli.consts import SECRET_SCAN_TYPE
from cycode.cli.models import DocumentDetections, Detection, Document

# we are using indexes like 10 20 30 to have space between for future columns inserts

# optional
SECRET_SHA_COLUMN = ColumnInfo(name='Secret SHA', index=31, width_secret=2)
COMMIT_SHA_COLUMN = ColumnInfo(name='Commit SHA', index=32)
VIOLATION_LENGTH_COLUMN = ColumnInfo(name='Violation Length', index=51)
VIOLATION_COLUMN = ColumnInfo(name='Violation', index=52, width_secret=2)
# required
ISSUE_TYPE_COLUMN = ColumnInfo(name='Issue Type', index=10, width_secret=2, width_iac=4, width_sast=7)
RULE_ID_COLUMN = ColumnInfo(name='Rule ID', index=20, width_secret=2, width_iac=3, width_sast=2)
FILE_PATH_COLUMN = ColumnInfo(name='File Path', index=30, width_secret=2, width_iac=3, width_sast=3)
LINE_NUMBER_COLUMN = ColumnInfo(name='Line Number', index=40)
COLUMN_NUMBER_COLUMN = ColumnInfo(name='Column Number', index=50)


class TablePrinter(BaseTablePrinter):
    def _print_results(self, results: List[DocumentDetections]) -> None:
        table = self._get_table()

        for detections in results:
            for detection in detections.detections:
                self._enrich_table_with_values(table, detection, detections.document)

        click.echo(table.get_table().draw())

    def _get_table(self) -> Table:
        """Returns map (under the hood) of table headers and their values"""
        columns = Table(self.scan_type)

        columns.add(ISSUE_TYPE_COLUMN)
        columns.add(RULE_ID_COLUMN)
        columns.add(FILE_PATH_COLUMN)
        columns.add(LINE_NUMBER_COLUMN)
        columns.add(COLUMN_NUMBER_COLUMN)

        if self._is_git_repository():
            columns.add(COMMIT_SHA_COLUMN)

        if self.scan_type == SECRET_SCAN_TYPE:
            columns.add(SECRET_SHA_COLUMN)
            columns.add(VIOLATION_LENGTH_COLUMN)
            columns.add(VIOLATION_COLUMN)

        return columns

    def _enrich_table_with_values(self, table: Table, detection: Detection, document: Document) -> None:
        self._enrich_table_with_detection_summary_values(table, detection, document)
        self._enrich_table_with_detection_code_segment_values(table, detection, document)

    def _enrich_table_with_detection_summary_values(
            self, table: Table, detection: Detection, document: Document
    ) -> None:
        issue_type = detection.message
        if self.scan_type == SECRET_SCAN_TYPE:
            issue_type = detection.type

        table.set(ISSUE_TYPE_COLUMN, issue_type)
        table.set(RULE_ID_COLUMN, detection.detection_rule_id)
        table.set(FILE_PATH_COLUMN, click.format_filename(document.path))
        table.set(SECRET_SHA_COLUMN, detection.detection_details.get('sha512', ''))
        table.set(COMMIT_SHA_COLUMN, detection.detection_details.get('commit_id', ''))

    def _enrich_table_with_detection_code_segment_values(
            self, table: Table, detection: Detection, document: Document
    ) -> None:
        detection_details = detection.detection_details

        detection_line = detection_details.get('line_in_file', -1)
        if self.scan_type == SECRET_SCAN_TYPE:
            detection_line = detection_details.get('line', -1)

        detection_column = get_position_in_line(document.content, detection_details.get('start_position', -1))
        violation_length = detection_details.get('length', -1)

        table.set(LINE_NUMBER_COLUMN, str(detection_line))
        table.set(COLUMN_NUMBER_COLUMN, str(detection_column))

        table.set(VIOLATION_LENGTH_COLUMN, f'{violation_length} chars')

        violation = ''
        file_content_lines = document.content.splitlines()
        if detection_line < len(file_content_lines):
            line = file_content_lines[detection_line]
            violation = line[detection_column: detection_column + violation_length]

            if not self.show_secret:
                violation = obfuscate_text(violation)

        table.set(VIOLATION_COLUMN, violation)
