from typing import TYPE_CHECKING, List

import click

from cycode.cli.consts import INFRA_CONFIGURATION_SCAN_TYPE, SAST_SCAN_TYPE, SECRET_SCAN_TYPE
from cycode.cli.models import Detection, Document
from cycode.cli.printers.tables.table import Table
from cycode.cli.printers.tables.table_models import ColumnInfoBuilder, ColumnWidthsConfig
from cycode.cli.printers.tables.table_printer_base import TablePrinterBase
from cycode.cli.utils.string_utils import get_position_in_line, obfuscate_text

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult

column_builder = ColumnInfoBuilder()

# Building must have strict order. Represents the order of the columns in the table (from left to right)
ISSUE_TYPE_COLUMN = column_builder.build(name='Issue Type')
RULE_ID_COLUMN = column_builder.build(name='Rule ID')
FILE_PATH_COLUMN = column_builder.build(name='File Path')
SECRET_SHA_COLUMN = column_builder.build(name='Secret SHA')
COMMIT_SHA_COLUMN = column_builder.build(name='Commit SHA')
LINE_NUMBER_COLUMN = column_builder.build(name='Line Number')
COLUMN_NUMBER_COLUMN = column_builder.build(name='Column Number')
VIOLATION_LENGTH_COLUMN = column_builder.build(name='Violation Length')
VIOLATION_COLUMN = column_builder.build(name='Violation')
SCAN_ID_COLUMN = column_builder.build(name='Scan ID')
REPORT_URL_COLUMN = column_builder.build(name='Report URL')

COLUMN_WIDTHS_CONFIG: ColumnWidthsConfig = {
    SECRET_SCAN_TYPE: {
        ISSUE_TYPE_COLUMN: 2,
        RULE_ID_COLUMN: 2,
        FILE_PATH_COLUMN: 2,
        SECRET_SHA_COLUMN: 2,
        VIOLATION_COLUMN: 2,
        SCAN_ID_COLUMN: 2,
    },
    INFRA_CONFIGURATION_SCAN_TYPE: {
        ISSUE_TYPE_COLUMN: 4,
        RULE_ID_COLUMN: 3,
        FILE_PATH_COLUMN: 3,
        SCAN_ID_COLUMN: 2,
    },
    SAST_SCAN_TYPE: {
        ISSUE_TYPE_COLUMN: 7,
        RULE_ID_COLUMN: 2,
        FILE_PATH_COLUMN: 3,
        SCAN_ID_COLUMN: 2,
    },
}


class TablePrinter(TablePrinterBase):
    def _print_results(self, local_scan_results: List['LocalScanResult']) -> None:
        table = self._get_table()
        if self.scan_type in COLUMN_WIDTHS_CONFIG:
            table.set_cols_width(COLUMN_WIDTHS_CONFIG[self.scan_type])

        for local_scan_result in local_scan_results:
            for document_detections in local_scan_result.document_detections:
                report_url = local_scan_result.report_url if local_scan_result.report_url else 'N/A'
                for detection in document_detections.detections:
                    table.set(REPORT_URL_COLUMN, report_url)
                    table.set(SCAN_ID_COLUMN, local_scan_result.scan_id)
                    self._enrich_table_with_values(table, detection, document_detections.document)

        self._print_table(table)

    def _get_table(self) -> Table:
        table = Table()

        table.add(ISSUE_TYPE_COLUMN)
        table.add(RULE_ID_COLUMN)
        table.add(FILE_PATH_COLUMN)
        table.add(LINE_NUMBER_COLUMN)
        table.add(COLUMN_NUMBER_COLUMN)
        table.add(SCAN_ID_COLUMN)

        if self._is_git_repository():
            table.add(COMMIT_SHA_COLUMN)

        if self.scan_type == SECRET_SCAN_TYPE:
            table.add(SECRET_SHA_COLUMN)
            table.add(VIOLATION_LENGTH_COLUMN)
            table.add(VIOLATION_COLUMN)

        if self.context.obj.get('report'):
            table.add(REPORT_URL_COLUMN)

        return table

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

        violation = ''
        file_content_lines = document.content.splitlines()
        if detection_line < len(file_content_lines):
            line = file_content_lines[detection_line]
            violation = line[detection_column : detection_column + violation_length]

            if not self.show_secret:
                violation = obfuscate_text(violation)

        table.set(LINE_NUMBER_COLUMN, str(detection_line))
        table.set(COLUMN_NUMBER_COLUMN, str(detection_column))
        table.set(VIOLATION_LENGTH_COLUMN, f'{violation_length} chars')
        table.set(VIOLATION_COLUMN, violation)
