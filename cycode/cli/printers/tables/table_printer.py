from typing import TYPE_CHECKING

from cycode.cli.cli_types import SeverityOption
from cycode.cli.consts import SECRET_SCAN_TYPE
from cycode.cli.models import Detection, Document
from cycode.cli.printers.tables.table import Table
from cycode.cli.printers.tables.table_models import ColumnInfoBuilder
from cycode.cli.printers.tables.table_printer_base import TablePrinterBase
from cycode.cli.printers.utils import is_git_diff_based_scan
from cycode.cli.printers.utils.detection_ordering.common_ordering import sort_and_group_detections_from_scan_result
from cycode.cli.utils.string_utils import get_position_in_line, obfuscate_text

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult

column_builder = ColumnInfoBuilder()

# Building must have strict order. Represents the order of the columns in the table (from left to right)
SEVERITY_COLUMN = column_builder.build(name='Severity')
ISSUE_TYPE_COLUMN = column_builder.build(name='Issue Type')
FILE_PATH_COLUMN = column_builder.build(name='File Path', highlight=False)
LINE_NUMBER_COLUMN = column_builder.build(name='Line')
COLUMN_NUMBER_COLUMN = column_builder.build(name='Column')
VIOLATION_COLUMN = column_builder.build(name='Violation', highlight=False)
VIOLATION_LENGTH_COLUMN = column_builder.build(name='Length')
SECRET_SHA_COLUMN = column_builder.build(name='Secret SHA')
COMMIT_SHA_COLUMN = column_builder.build(name='Commit SHA')


class TablePrinter(TablePrinterBase):
    def _print_results(self, local_scan_results: list['LocalScanResult']) -> None:
        table = self._get_table()

        detections, group_separator_indexes = sort_and_group_detections_from_scan_result(local_scan_results)
        for detection, document in detections:
            self._enrich_table_with_values(table, detection, document)

        table.set_group_separator_indexes(group_separator_indexes)

        self._print_table(table)

    def _get_table(self) -> Table:
        table = Table()

        table.add_column(SEVERITY_COLUMN)
        table.add_column(ISSUE_TYPE_COLUMN)
        table.add_column(FILE_PATH_COLUMN)
        table.add_column(LINE_NUMBER_COLUMN)
        table.add_column(COLUMN_NUMBER_COLUMN)

        if is_git_diff_based_scan(self.command_scan_type):
            table.add_column(COMMIT_SHA_COLUMN)

        if self.scan_type == SECRET_SCAN_TYPE:
            table.add_column(SECRET_SHA_COLUMN)
            table.add_column(VIOLATION_LENGTH_COLUMN)
            table.add_column(VIOLATION_COLUMN)

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

        table.add_cell(SEVERITY_COLUMN, SeverityOption(detection.severity))
        table.add_cell(ISSUE_TYPE_COLUMN, issue_type)
        table.add_file_path_cell(FILE_PATH_COLUMN, document.path)
        table.add_cell(SECRET_SHA_COLUMN, detection.detection_details.get('sha512', ''))
        table.add_cell(COMMIT_SHA_COLUMN, detection.detection_details.get('commit_id', ''))

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

        table.add_cell(LINE_NUMBER_COLUMN, str(detection_line))
        table.add_cell(COLUMN_NUMBER_COLUMN, str(detection_column))
        table.add_cell(VIOLATION_LENGTH_COLUMN, f'{violation_length} chars')
        table.add_cell(VIOLATION_COLUMN, violation)
