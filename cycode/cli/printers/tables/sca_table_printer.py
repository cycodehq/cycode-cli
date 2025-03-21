from collections import defaultdict
from typing import TYPE_CHECKING, Dict, List, Set, Tuple

import typer

from cycode.cli.cli_types import SeverityOption
from cycode.cli.consts import LICENSE_COMPLIANCE_POLICY_ID, PACKAGE_VULNERABILITY_POLICY_ID
from cycode.cli.models import Detection
from cycode.cli.printers.tables.table import Table
from cycode.cli.printers.tables.table_models import ColumnInfoBuilder
from cycode.cli.printers.tables.table_printer_base import TablePrinterBase
from cycode.cli.utils.string_utils import shortcut_dependency_paths

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult

column_builder = ColumnInfoBuilder()

# Building must have strict order. Represents the order of the columns in the table (from left to right)
SEVERITY_COLUMN = column_builder.build(name='Severity')
REPOSITORY_COLUMN = column_builder.build(name='Repository')
CODE_PROJECT_COLUMN = column_builder.build(name='Code Project', highlight=False)  # File path to the manifest file
ECOSYSTEM_COLUMN = column_builder.build(name='Ecosystem', highlight=False)
PACKAGE_COLUMN = column_builder.build(name='Package', highlight=False)
CVE_COLUMNS = column_builder.build(name='CVE', highlight=False)
DEPENDENCY_PATHS_COLUMN = column_builder.build(name='Dependency Paths')
UPGRADE_COLUMN = column_builder.build(name='Upgrade')
LICENSE_COLUMN = column_builder.build(name='License', highlight=False)
DIRECT_DEPENDENCY_COLUMN = column_builder.build(name='Direct Dependency')
DEVELOPMENT_DEPENDENCY_COLUMN = column_builder.build(name='Development Dependency')


class ScaTablePrinter(TablePrinterBase):
    def _print_results(self, local_scan_results: List['LocalScanResult']) -> None:
        aggregation_report_url = self.ctx.obj.get('aggregation_report_url')
        detections_per_policy_id = self._extract_detections_per_policy_id(local_scan_results)
        for policy_id, detections in detections_per_policy_id.items():
            table = self._get_table(policy_id)

            resulting_detections, group_separator_indexes = self._sort_and_group_detections(detections)
            for detection in resulting_detections:
                self._enrich_table_with_values(policy_id, table, detection)

            table.set_group_separator_indexes(group_separator_indexes)

            self._print_summary_issues(len(detections), self._get_title(policy_id))
            self._print_table(table)

        self._print_report_urls(local_scan_results, aggregation_report_url)

    @staticmethod
    def _get_title(policy_id: str) -> str:
        if policy_id == PACKAGE_VULNERABILITY_POLICY_ID:
            return 'Dependency Vulnerabilities'
        if policy_id == LICENSE_COMPLIANCE_POLICY_ID:
            return 'License Compliance'

        return 'Unknown'

    @staticmethod
    def __group_by(detections: List[Detection], details_field_name: str) -> Dict[str, List[Detection]]:
        grouped = defaultdict(list)
        for detection in detections:
            grouped[detection.detection_details.get(details_field_name)].append(detection)
        return grouped

    @staticmethod
    def __severity_sort_key(detection: Detection) -> int:
        severity = detection.detection_details.get('advisory_severity', 'unknown')
        return SeverityOption.get_member_weight(severity)

    def _sort_detections_by_severity(self, detections: List[Detection]) -> List[Detection]:
        return sorted(detections, key=self.__severity_sort_key, reverse=True)

    @staticmethod
    def __package_sort_key(detection: Detection) -> int:
        return detection.detection_details.get('package_name')

    def _sort_detections_by_package(self, detections: List[Detection]) -> List[Detection]:
        return sorted(detections, key=self.__package_sort_key)

    def _sort_and_group_detections(self, detections: List[Detection]) -> Tuple[List[Detection], Set[int]]:
        """Sort detections by severity and group by repository, code project and package name.

        Note:
            Code Project is path to the manifest file.

            Grouping by code projects also groups by ecosystem.
            Because manifest files are unique per ecosystem.
        """
        resulting_detections = []
        group_separator_indexes = set()

        # we sort detections by package name to make persist output order
        sorted_detections = self._sort_detections_by_package(detections)

        grouped_by_repository = self.__group_by(sorted_detections, 'repository_name')
        for repository_group in grouped_by_repository.values():
            grouped_by_code_project = self.__group_by(repository_group, 'file_name')
            for code_project_group in grouped_by_code_project.values():
                grouped_by_package = self.__group_by(code_project_group, 'package_name')
                for package_group in grouped_by_package.values():
                    group_separator_indexes.add(len(resulting_detections) - 1)  # indexing starts from 0
                    resulting_detections.extend(self._sort_detections_by_severity(package_group))

        return resulting_detections, group_separator_indexes

    def _get_table(self, policy_id: str) -> Table:
        table = Table()

        if policy_id == PACKAGE_VULNERABILITY_POLICY_ID:
            table.add_column(CVE_COLUMNS)
            table.add_column(UPGRADE_COLUMN)
        elif policy_id == LICENSE_COMPLIANCE_POLICY_ID:
            table.add_column(LICENSE_COLUMN)

        if self._is_git_repository():
            table.add_column(REPOSITORY_COLUMN)

        table.add_column(SEVERITY_COLUMN)
        table.add_column(CODE_PROJECT_COLUMN)
        table.add_column(ECOSYSTEM_COLUMN)
        table.add_column(PACKAGE_COLUMN)
        table.add_column(DIRECT_DEPENDENCY_COLUMN)
        table.add_column(DEVELOPMENT_DEPENDENCY_COLUMN)
        table.add_column(DEPENDENCY_PATHS_COLUMN)

        return table

    @staticmethod
    def _enrich_table_with_values(policy_id: str, table: Table, detection: Detection) -> None:
        detection_details = detection.detection_details

        severity = None
        if policy_id == PACKAGE_VULNERABILITY_POLICY_ID:
            severity = detection_details.get('advisory_severity')
        elif policy_id == LICENSE_COMPLIANCE_POLICY_ID:
            severity = detection.severity

        if not severity:
            severity = 'N/A'

        table.add_cell(SEVERITY_COLUMN, severity, SeverityOption.get_member_color(severity))

        table.add_cell(REPOSITORY_COLUMN, detection_details.get('repository_name'))
        table.add_file_path_cell(CODE_PROJECT_COLUMN, detection_details.get('file_name'))
        table.add_cell(ECOSYSTEM_COLUMN, detection_details.get('ecosystem'))
        table.add_cell(PACKAGE_COLUMN, detection_details.get('package_name'))

        dependency_bool_to_color = {
            True: 'green',
            False: 'red',
        }  # by default, not colored (None)
        table.add_cell(
            column=DIRECT_DEPENDENCY_COLUMN,
            value=detection_details.get('is_direct_dependency_str'),
            color=dependency_bool_to_color.get(detection_details.get('is_direct_dependency')),
        )
        table.add_cell(
            column=DEVELOPMENT_DEPENDENCY_COLUMN,
            value=detection_details.get('is_dev_dependency_str'),
            color=dependency_bool_to_color.get(detection_details.get('is_dev_dependency')),
        )

        dependency_paths = 'N/A'
        dependency_paths_raw = detection_details.get('dependency_paths')
        if dependency_paths_raw:
            dependency_paths = shortcut_dependency_paths(dependency_paths_raw)
        table.add_cell(DEPENDENCY_PATHS_COLUMN, dependency_paths)

        upgrade = ''
        alert = detection_details.get('alert')
        if alert and alert.get('first_patched_version'):
            upgrade = f'{alert.get("vulnerable_requirements")} -> {alert.get("first_patched_version")}'
        table.add_cell(UPGRADE_COLUMN, upgrade)

        table.add_cell(CVE_COLUMNS, detection_details.get('vulnerability_id'))
        table.add_cell(LICENSE_COLUMN, detection_details.get('license'))

    @staticmethod
    def _print_summary_issues(detections_count: int, title: str) -> None:
        typer.echo(f'⛔ Found {detections_count} issues of type: {typer.style(title, bold=True)}')

    @staticmethod
    def _extract_detections_per_policy_id(
        local_scan_results: List['LocalScanResult'],
    ) -> Dict[str, List[Detection]]:
        detections_to_policy_id = defaultdict(list)

        for local_scan_result in local_scan_results:
            for document_detection in local_scan_result.document_detections:
                for detection in document_detection.detections:
                    detections_to_policy_id[detection.detection_type_id].append(detection)

        # sort dict by keys (policy id) to make persist output order
        return dict(sorted(detections_to_policy_id.items(), reverse=True))
