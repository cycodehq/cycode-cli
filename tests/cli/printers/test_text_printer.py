import io
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from cycode.cli.consts import (
    LICENSE_COMPLIANCE_POLICY_ID,
    PACKAGE_VULNERABILITY_POLICY_ID,
    UNMAINTAINED_PACKAGE_POLICY_ID,
)
from cycode.cli.models import Document, DocumentDetections, LocalScanResult
from cycode.cli.printers.text_printer import TextPrinter
from cycode.cyclient.models import Detection


@pytest.fixture
def output() -> io.StringIO:
    return io.StringIO()


@pytest.fixture
def printer(output: io.StringIO) -> TextPrinter:
    ctx = MagicMock()
    ctx.obj = {'scan_type': 'sca', 'show_secret': False}
    ctx.info_name = 'path'
    return TextPrinter(ctx, Console(file=output, width=200), Console(stderr=True))


def _make_detection(policy_id: str, **details: object) -> Detection:
    return Detection(
        detection_type_id=policy_id,
        type='UnmaintainedPackage',
        message='Package is unmaintained',
        detection_details=dict(details),
        detection_rule_id='rule-id',
        severity='Medium',
    )


def _render(printer: TextPrinter, output: io.StringIO, detection: Detection) -> str:
    document = Document(path='package-lock.json', content='{}')
    printer.print_scan_results(
        [
            LocalScanResult(
                scan_id='scan-id',
                report_url=None,
                document_detections=[DocumentDetections(document=document, detections=[detection])],
                issue_detected=True,
                detections_count=1,
                relevant_detections_count=1,
            )
        ]
    )
    return output.getvalue()


def test_unmaintained_package_prints_the_score_and_report(printer: TextPrinter, output: io.StringIO) -> None:
    detection = _make_detection(
        UNMAINTAINED_PACKAGE_POLICY_ID,
        ossf={
            'score': 4.1,
            'scorecard_report_url': 'https://scorecard.dev/viewer/?uri=github.com/a/b',
            'checks': [{'name': 'Maintained', 'score': 0, 'reason': '0 commit(s) in the last 90 days'}],
        },
    )

    result = _render(printer, output, detection)

    assert 'Maintained score: 0' in result
    assert 'OSSF Scorecard score: 4.1' in result
    assert 'Scorecard report: https://scorecard.dev/viewer/?uri=github.com/a/b' in result
    assert 'License' not in result


def test_unmaintained_package_without_ossf_details(printer: TextPrinter, output: io.StringIO) -> None:
    detection = _make_detection(UNMAINTAINED_PACKAGE_POLICY_ID)

    result = _render(printer, output, detection)

    assert 'Maintained score: N/A' in result
    assert 'OSSF Scorecard score: N/A' in result
    assert 'Scorecard report: N/A' in result


def test_unmaintained_package_with_zero_score(printer: TextPrinter, output: io.StringIO) -> None:
    detection = _make_detection(
        UNMAINTAINED_PACKAGE_POLICY_ID,
        ossf={'score': 0, 'scorecard_report_url': '', 'checks': [{'name': 'Maintained', 'score': 0}]},
    )

    result = _render(printer, output, detection)

    assert 'Maintained score: 0' in result
    assert 'OSSF Scorecard score: 0' in result
    assert 'Scorecard report: N/A' in result


def test_unmaintained_package_without_maintained_check(printer: TextPrinter, output: io.StringIO) -> None:
    detection = _make_detection(
        UNMAINTAINED_PACKAGE_POLICY_ID,
        ossf={'score': 1.5, 'checks': [{'name': 'License', 'score': 10}]},
    )

    result = _render(printer, output, detection)

    assert 'Maintained score: N/A' in result
    assert 'OSSF Scorecard score: 1.5' in result


def test_license_compliance_still_prints_the_license(printer: TextPrinter, output: io.StringIO) -> None:
    detection = _make_detection(LICENSE_COMPLIANCE_POLICY_ID, license='GPL-3.0')

    result = _render(printer, output, detection)

    assert 'License: GPL-3.0' in result
    assert 'OSSF' not in result


def test_package_vulnerability_still_prints_the_patched_version(printer: TextPrinter, output: io.StringIO) -> None:
    detection = _make_detection(
        PACKAGE_VULNERABILITY_POLICY_ID,
        alert={'first_patched_version': '4.17.21'},
    )

    result = _render(printer, output, detection)

    assert 'First patched version: 4.17.21' in result
    assert 'OSSF' not in result
