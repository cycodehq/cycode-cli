from typing import TYPE_CHECKING, Callable

from cycode.cli.consts import (
    LICENSE_COMPLIANCE_POLICY_ID,
    PACKAGE_VULNERABILITY_POLICY_ID,
    SCA_SCAN_TYPE,
    UNMAINTAINED_PACKAGE_POLICY_ID,
)
from cycode.cli.printers.utils.detection_data import get_detection_clickable_cwe_cve
from cycode.cli.printers.utils.sca_ossf import get_maintained_score, get_ossf_report_url, get_ossf_score

if TYPE_CHECKING:
    from cycode.cyclient.models import Detection

_NOT_AVAILABLE = 'N/A'


def _package_vulnerability_details(detection: 'Detection') -> list[tuple[str, str]]:
    alert = detection.detection_details.get('alert') or {}
    return [
        ('CVEs', get_detection_clickable_cwe_cve(SCA_SCAN_TYPE, detection) or _NOT_AVAILABLE),
        ('First patched version', alert.get('first_patched_version') or 'Not fixed'),
    ]


def _license_compliance_details(detection: 'Detection') -> list[tuple[str, str]]:
    return [('License', detection.detection_details.get('license') or _NOT_AVAILABLE)]


def _unmaintained_package_details(detection: 'Detection') -> list[tuple[str, str]]:
    detection_details = detection.detection_details
    maintained_score = get_maintained_score(detection_details)
    ossf_score = get_ossf_score(detection_details)

    return [
        ('Maintained score', _NOT_AVAILABLE if maintained_score is None else str(maintained_score)),
        ('OSSF Scorecard score', _NOT_AVAILABLE if ossf_score is None else str(ossf_score)),
        ('Scorecard report', get_ossf_report_url(detection_details) or _NOT_AVAILABLE),
    ]


_DETAILS_BY_POLICY: dict[str, Callable[['Detection'], list[tuple[str, str]]]] = {
    PACKAGE_VULNERABILITY_POLICY_ID: _package_vulnerability_details,
    LICENSE_COMPLIANCE_POLICY_ID: _license_compliance_details,
    UNMAINTAINED_PACKAGE_POLICY_ID: _unmaintained_package_details,
}


def get_sca_policy_details(detection: 'Detection') -> list[tuple[str, str]]:
    """Labelled fields specific to the SCA policy that raised the detection, in display order.

    A policy with no entry contributes nothing rather than borrowing another policy's fields, so a new one shows
    no details until it is added here.
    """
    build_details = _DETAILS_BY_POLICY.get(detection.detection_type_id)

    return build_details(detection) if build_details else []
