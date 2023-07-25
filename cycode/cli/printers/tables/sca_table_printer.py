from collections import defaultdict
from typing import TYPE_CHECKING, Dict, List

import click

from cycode.cli.consts import LICENSE_COMPLIANCE_POLICY_ID, PACKAGE_VULNERABILITY_POLICY_ID
from cycode.cli.models import Detection
from cycode.cli.printers.tables.table import Table
from cycode.cli.printers.tables.table_models import ColumnInfoBuilder, ColumnWidths
from cycode.cli.printers.tables.table_printer_base import TablePrinterBase
from cycode.cli.utils.string_utils import shortcut_dependency_paths

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult


column_builder = ColumnInfoBuilder()

# Building must have strict order. Represents the order of the columns in the table (from left to right)
SEVERITY_COLUMN = column_builder.build(name='Severity')
REPOSITORY_COLUMN = column_builder.build(name='Repository')

FILE_PATH_COLUMN = column_builder.build(name='File Path')
ECOSYSTEM_COLUMN = column_builder.build(name='Ecosystem')
DEPENDENCY_NAME_COLUMN = column_builder.build(name='Dependency Name')
DIRECT_DEPENDENCY_COLUMN = column_builder.build(name='Direct Dependency')
DEVELOPMENT_DEPENDENCY_COLUMN = column_builder.build(name='Development Dependency')
DEPENDENCY_PATHS_COLUMN = column_builder.build(name='Dependency Paths')

CVE_COLUMNS = column_builder.build(name='CVE')
UPGRADE_COLUMN = column_builder.build(name='Upgrade')
LICENSE_COLUMN = column_builder.build(name='License')

COLUMN_WIDTHS_CONFIG: ColumnWidths = {
    REPOSITORY_COLUMN: 2,
    FILE_PATH_COLUMN: 3,
    CVE_COLUMNS: 5,
    UPGRADE_COLUMN: 3,
    LICENSE_COLUMN: 2,
}


class ScaTablePrinter(TablePrinterBase):
    def _print_results(self, local_scan_results: List['LocalScanResult']) -> None:
        detections_per_policy_id = self._extract_detections_per_policy_id(local_scan_results)
        for policy_id, detections in detections_per_policy_id.items():
            table = self._get_table(policy_id)
            table.set_cols_width(COLUMN_WIDTHS_CONFIG)

            for detection in detections:
                self._enrich_table_with_values(table, detection)

            self._print_summary_issues(len(detections), self._get_title(policy_id))
            self._print_table(table)

        self._print_report_urls(local_scan_results)

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
            table.add(SEVERITY_COLUMN)
            table.add(CVE_COLUMNS)
            table.add(UPGRADE_COLUMN)
        elif policy_id == LICENSE_COMPLIANCE_POLICY_ID:
            table.add(LICENSE_COLUMN)

        if self._is_git_repository():
            table.add(REPOSITORY_COLUMN)

        table.add(FILE_PATH_COLUMN)
        table.add(ECOSYSTEM_COLUMN)
        table.add(DEPENDENCY_NAME_COLUMN)
        table.add(DIRECT_DEPENDENCY_COLUMN)
        table.add(DEVELOPMENT_DEPENDENCY_COLUMN)
        table.add(DEPENDENCY_PATHS_COLUMN)

        return table

    @staticmethod
    def _enrich_table_with_values(table: Table, detection: Detection) -> None:
        detection_details = detection.detection_details

        table.set(SEVERITY_COLUMN, detection_details.get('advisory_severity'))
        table.set(REPOSITORY_COLUMN, detection_details.get('repository_name'))

        table.set(FILE_PATH_COLUMN, detection_details.get('file_name'))
        table.set(ECOSYSTEM_COLUMN, detection_details.get('ecosystem'))
        table.set(DEPENDENCY_NAME_COLUMN, detection_details.get('package_name'))
        table.set(DIRECT_DEPENDENCY_COLUMN, detection_details.get('is_direct_dependency_str'))
        table.set(DEVELOPMENT_DEPENDENCY_COLUMN, detection_details.get('is_dev_dependency_str'))

        dependency_paths = 'N/A'
        dependency_paths_raw = detection_details.get('dependency_paths')
        if dependency_paths_raw:
            dependency_paths = shortcut_dependency_paths(dependency_paths_raw)
        table.set(DEPENDENCY_PATHS_COLUMN, dependency_paths)

        upgrade = ''
        alert = detection_details.get('alert')
        if alert and alert.get('first_patched_version'):
            upgrade = f'{alert.get("vulnerable_requirements")} -> {alert.get("first_patched_version")}'
        table.set(UPGRADE_COLUMN, upgrade)

        table.set(CVE_COLUMNS, detection_details.get('vulnerability_id'))
        table.set(LICENSE_COLUMN, detection_details.get('license'))

    @staticmethod
    def _print_report_urls(local_scan_results: List['LocalScanResult']) -> None:
        report_urls = [scan_result.report_url for scan_result in local_scan_results if scan_result.report_url]
        if not report_urls:
            return

        click.echo('Report URLs:')
        for report_url in report_urls:
            click.echo(f'- {report_url}')

    @staticmethod
    def _print_summary_issues(detections_count: int, title: str) -> None:
        click.echo(f'⛔ Found {detections_count} issues of type: {click.style(title, bold=True)}')

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
