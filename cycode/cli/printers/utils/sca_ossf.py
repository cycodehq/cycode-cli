from typing import Any, Optional

_MAINTAINED_CHECK_NAME = 'maintained'


def _get_ossf_details(detection_details: dict) -> dict:
    return detection_details.get('ossf') or {}


def get_ossf_score(detection_details: dict) -> Optional[Any]:
    return _get_ossf_details(detection_details).get('score')


def get_ossf_report_url(detection_details: dict) -> Optional[str]:
    return _get_ossf_details(detection_details).get('scorecard_report_url')


def get_maintained_score(detection_details: dict) -> Optional[Any]:
    for check in _get_ossf_details(detection_details).get('checks') or []:
        if str(check.get('name', '')).lower() == _MAINTAINED_CHECK_NAME:
            return check.get('score')

    return None
