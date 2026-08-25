from typing import Any, Optional


def _get_ossf_details(detection_details: dict) -> dict:
    """Package health lives in a nested "ossf" object, absent when no scorecard was resolved."""
    return detection_details.get('ossf') or {}


def get_ossf_score(detection_details: dict) -> Optional[Any]:
    return _get_ossf_details(detection_details).get('score')


def get_ossf_report_url(detection_details: dict) -> Optional[str]:
    return _get_ossf_details(detection_details).get('scorecard_report_url')
