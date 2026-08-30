from cycode.cli.consts import (
    LICENSE_COMPLIANCE_POLICY_ID,
    PACKAGE_VULNERABILITY_POLICY_ID,
    UNMAINTAINED_PACKAGE_POLICY_ID,
)
from cycode.cli.printers.utils.sca_policy_details import get_sca_policy_details
from cycode.cyclient.models import Detection


def _make_detection(policy_id: str, **details: object) -> Detection:
    return Detection(
        detection_type_id=policy_id,
        type='sca',
        message='message',
        detection_details=dict(details),
        detection_rule_id='rule-id',
        severity='Medium',
    )


def test_package_vulnerability_reports_the_patched_version() -> None:
    detection = _make_detection(PACKAGE_VULNERABILITY_POLICY_ID, alert={'first_patched_version': '4.17.21'})

    assert get_sca_policy_details(detection) == [('First patched version', '4.17.21')]


def test_package_vulnerability_without_a_patch() -> None:
    detection = _make_detection(PACKAGE_VULNERABILITY_POLICY_ID, alert={'first_patched_version': None})

    assert get_sca_policy_details(detection) == [('First patched version', 'Not fixed')]


def test_license_compliance_reports_the_license() -> None:
    detection = _make_detection(LICENSE_COMPLIANCE_POLICY_ID, license='GPL-3.0')

    assert get_sca_policy_details(detection) == [('License', 'GPL-3.0')]


def test_license_compliance_without_a_license() -> None:
    detection = _make_detection(LICENSE_COMPLIANCE_POLICY_ID)

    assert get_sca_policy_details(detection) == [('License', 'N/A')]


def test_unmaintained_package_reports_the_maintained_check_first() -> None:
    detection = _make_detection(
        UNMAINTAINED_PACKAGE_POLICY_ID,
        ossf={
            'score': 4.1,
            'scorecard_report_url': 'https://scorecard.dev/viewer/?uri=github.com/a/b',
            'checks': [{'name': 'Maintained', 'score': 0}],
        },
    )

    assert get_sca_policy_details(detection) == [
        ('Maintained score', '0'),
        ('OSSF Scorecard score', '4.1'),
        ('Scorecard report', 'https://scorecard.dev/viewer/?uri=github.com/a/b'),
    ]


def test_unmaintained_package_without_a_scorecard() -> None:
    detection = _make_detection(UNMAINTAINED_PACKAGE_POLICY_ID)

    assert get_sca_policy_details(detection) == [
        ('Maintained score', 'N/A'),
        ('OSSF Scorecard score', 'N/A'),
        ('Scorecard report', 'N/A'),
    ]


def test_an_unregistered_policy_contributes_nothing() -> None:
    """A policy with no entry must stay silent rather than borrow another policy's fields.

    Before this was keyed by policy, an unmaintained detection fell through to the license branch and rendered
    an empty License row. A fourth policy would do the same.
    """
    detection = _make_detection('00000000-0000-0000-0000-000000000000', license='GPL-3.0', alert={})

    assert get_sca_policy_details(detection) == []
