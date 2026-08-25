from unittest.mock import MagicMock

import pytest
from rich.console import Console

from cycode.cli.consts import (
    LICENSE_COMPLIANCE_POLICY_ID,
    PACKAGE_VULNERABILITY_POLICY_ID,
    UNMAINTAINED_PACKAGE_POLICY_ID,
)
from cycode.cli.printers.tables.sca_table_printer import (
    CVE_COLUMNS,
    LICENSE_COLUMN,
    OSSF_SCORE_COLUMN,
    UPGRADE_COLUMN,
    ScaTablePrinter,
)
from cycode.cyclient.models import Detection


@pytest.fixture
def printer() -> ScaTablePrinter:
    ctx = MagicMock()
    ctx.obj = {'scan_type': 'sca'}
    ctx.info_name = 'path'
    return ScaTablePrinter(ctx, Console(), Console(stderr=True))


def _make_detection(policy_id: str, **details: object) -> Detection:
    return Detection(
        detection_type_id=policy_id,
        type='Unmaintained packages',
        message='Package is unmaintained',
        detection_details=dict(details),
        detection_rule_id='rule-id',
        severity='Medium',
    )


def test_get_title_unmaintained_packages() -> None:
    assert ScaTablePrinter._get_title(UNMAINTAINED_PACKAGE_POLICY_ID) == 'Unmaintained Packages'


def test_get_title_known_policies_are_not_changed() -> None:
    assert ScaTablePrinter._get_title(PACKAGE_VULNERABILITY_POLICY_ID) == 'Dependency Vulnerabilities'
    assert ScaTablePrinter._get_title(LICENSE_COMPLIANCE_POLICY_ID) == 'License Compliance'


def test_get_title_unknown_policy() -> None:
    assert ScaTablePrinter._get_title('not-a-known-policy-id') == 'Unknown'


def test_get_table_unmaintained_packages_columns(printer: ScaTablePrinter) -> None:
    columns = printer._get_table(UNMAINTAINED_PACKAGE_POLICY_ID).get_columns_info()

    assert OSSF_SCORE_COLUMN in columns
    assert CVE_COLUMNS not in columns
    assert UPGRADE_COLUMN not in columns
    assert LICENSE_COLUMN not in columns


def test_get_table_unmaintained_packages_column_order(printer: ScaTablePrinter) -> None:
    column_names = [column.name for column in printer._get_table(UNMAINTAINED_PACKAGE_POLICY_ID).get_columns_info()]

    assert column_names == [
        'Severity',
        'Code Project',
        'Ecosystem',
        'Package',
        'OSSF Score',
        'Dependency Paths',
        'Direct Dependency',
        'Development Dependency',
    ]


def test_get_table_other_policies_do_not_get_the_score_column(printer: ScaTablePrinter) -> None:
    assert OSSF_SCORE_COLUMN not in printer._get_table(PACKAGE_VULNERABILITY_POLICY_ID).get_columns_info()
    assert OSSF_SCORE_COLUMN not in printer._get_table(LICENSE_COMPLIANCE_POLICY_ID).get_columns_info()


def test_enrich_table_with_values_populates_the_score(printer: ScaTablePrinter) -> None:
    table = printer._get_table(UNMAINTAINED_PACKAGE_POLICY_ID)
    detection = _make_detection(
        UNMAINTAINED_PACKAGE_POLICY_ID,
        file_path='/repo/package.json',
        ecosystem='npm',
        package_name='left-pad',
        package_version='1.0.0',
        ossf={'score': 1.5, 'scorecard_report_url': 'https://scorecard.dev/viewer/?uri=github.com/example/left-pad'},
    )

    ScaTablePrinter._enrich_table_with_values(table, detection)

    row = table.get_rows()[0]
    score_index = table.get_columns_info().index(OSSF_SCORE_COLUMN)
    assert row[score_index] == '1.5'


def test_enrich_table_with_values_missing_score(printer: ScaTablePrinter) -> None:
    table = printer._get_table(UNMAINTAINED_PACKAGE_POLICY_ID)
    detection = _make_detection(UNMAINTAINED_PACKAGE_POLICY_ID, file_path='/repo/package.json', package_name='left-pad')

    ScaTablePrinter._enrich_table_with_values(table, detection)

    row = table.get_rows()[0]
    score_index = table.get_columns_info().index(OSSF_SCORE_COLUMN)
    assert row[score_index] == 'N/A'
