from collections import defaultdict
from typing import TYPE_CHECKING

from cycode.cli.cli_types import SeverityOption
from cycode.cli.consts import LICENSE_COMPLIANCE_POLICY_ID, PACKAGE_VULNERABILITY_POLICY_ID
from cycode.cli.models import Detection
from cycode.cli.printers.tables.table import Table
from cycode.cli.printers.tables.table_models import ColumnInfoBuilder
from cycode.cli.printers.tables.table_printer_base import TablePrinterBase
from cycode.cli.printers.utils import is_git_diff_based_scan
from cycode.cli.printers.utils.detection_ordering.sca_ordering import sort_and_group_detections
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
    def _print_results(self, local_scan_results: list['LocalScanResult']) -> None:
        detections_per_policy_id = self._extract_detections_per_policy_id(local_scan_results)
        for policy_id, detections in detections_per_policy_id.items():
            table = self._get_table(policy_id)

            resulting_detections, group_separator_indexes = sort_and_group_detections(detections)
            for detection in resulting_detections:
                self._enrich_table_with_values(table, detection)

            table.set_group_separator_indexes(group_separator_indexes)

            self._print_summary_issues(len(detections), self._get_title(policy_id))
            self._print_table(table)

    @staticmethod
    def _get_title(policy_id: str) -> str:
        if policy_id == PACKAGE_VULNERABILITY_POLICY_ID:
            return 'Dependency Vulnerabilities'
        if policy_id == LICENSE_COMPLIANCE_POLICY_ID:
            return 'License Compliance'

        return 'Unknown'

    def _get_table(self, policy_id: str) -> Table:
        table = Table()

        if policy_id == PACKAGE_VULNERABILITY_POLICY_ID:
            table.add_column(CVE_COLUMNS)
            table.add_column(UPGRADE_COLUMN)
        elif policy_id == LICENSE_COMPLIANCE_POLICY_ID:
            table.add_column(LICENSE_COLUMN)

        if is_git_diff_based_scan(self.command_scan_type):
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
    def _enrich_table_with_values(table: Table, detection: Detection) -> None:
        detection_details = detection.detection_details

        if detection.severity:
            table.add_cell(SEVERITY_COLUMN, SeverityOption(detection.severity))
        else:
            table.add_cell(SEVERITY_COLUMN, 'N/A')

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

    def _print_summary_issues(self, detections_count: int, title: str) -> None:
        self.console.print(f'[bold]Cycode found {detections_count} violations of type: [cyan]{title}[/]')

    @staticmethod
    def _extract_detections_per_policy_id(
        local_scan_results: list['LocalScanResult'],
    ) -> dict[str, list[Detection]]:
        detections_to_policy_id = defaultdict(list)

        for local_scan_result in local_scan_results:
            for document_detection in local_scan_result.document_detections:
                for detection in document_detection.detections:
                    detections_to_policy_id[detection.detection_type_id].append(detection)

        # sort dict by keys (policy id) to make persist output order
        return dict(sorted(detections_to_policy_id.items(), reverse=True))
