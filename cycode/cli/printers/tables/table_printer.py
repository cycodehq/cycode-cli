from collections import defaultdict
from typing import TYPE_CHECKING, List, Set, Tuple

from cycode.cli.cli_types import SeverityOption
from cycode.cli.consts import SECRET_SCAN_TYPE
from cycode.cli.models import Detection, Document
from cycode.cli.printers.tables.table import Table
from cycode.cli.printers.tables.table_models import ColumnInfoBuilder
from cycode.cli.printers.tables.table_printer_base import TablePrinterBase
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
    def _print_results(self, local_scan_results: List['LocalScanResult']) -> None:
        table = self._get_table()

        detections_with_documents = []
        for local_scan_result in local_scan_results:
            for document_detections in local_scan_result.document_detections:
                detections_with_documents.extend(
                    [(detection, document_detections.document) for detection in document_detections.detections]
                )

        detections, group_separator_indexes = self._sort_and_group_detections(detections_with_documents)
        for detection, document in detections:
            self._enrich_table_with_values(table, detection, document)

        table.set_group_separator_indexes(group_separator_indexes)

        self._print_table(table)
        self._print_report_urls(local_scan_results, self.ctx.obj.get('aggregation_report_url'))

    @staticmethod
    def __severity_sort_key(detection_with_document: Tuple[Detection, Document]) -> int:
        detection, _ = detection_with_document
        severity = detection.severity if detection.severity else ''
        return SeverityOption.get_member_weight(severity)

    def _sort_detections_by_severity(
        self, detections_with_documents: List[Tuple[Detection, Document]]
    ) -> List[Tuple[Detection, Document]]:
        return sorted(detections_with_documents, key=self.__severity_sort_key, reverse=True)

    @staticmethod
    def __file_path_sort_key(detection_with_document: Tuple[Detection, Document]) -> str:
        _, document = detection_with_document
        return document.path

    def _sort_detections_by_file_path(
        self, detections_with_documents: List[Tuple[Detection, Document]]
    ) -> List[Tuple[Detection, Document]]:
        return sorted(detections_with_documents, key=self.__file_path_sort_key)

    def _sort_and_group_detections(
        self, detections_with_documents: List[Tuple[Detection, Document]]
    ) -> Tuple[List[Tuple[Detection, Document]], Set[int]]:
        """Sort detections by severity and group by file name."""
        detections = []
        group_separator_indexes = set()

        # we sort detections by file path to make persist output order
        sorted_detections = self._sort_detections_by_file_path(detections_with_documents)

        grouped_by_file_path = defaultdict(list)
        for detection, document in sorted_detections:
            grouped_by_file_path[document.path].append((detection, document))

        for file_path_group in grouped_by_file_path.values():
            group_separator_indexes.add(len(detections) - 1)  # indexing starts from 0
            detections.extend(self._sort_detections_by_severity(file_path_group))

        return detections, group_separator_indexes

    def _get_table(self) -> Table:
        table = Table()

        table.add_column(SEVERITY_COLUMN)
        table.add_column(ISSUE_TYPE_COLUMN)
        table.add_column(FILE_PATH_COLUMN)
        table.add_column(LINE_NUMBER_COLUMN)
        table.add_column(COLUMN_NUMBER_COLUMN)

        if self._is_git_repository():
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

        table.add_cell(SEVERITY_COLUMN, detection.severity, SeverityOption.get_member_color(detection.severity))
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
