from cycode.cli.apps.scan.detection_excluder import _does_severity_match_severity_threshold


def test_does_severity_match_severity_threshold() -> None:
    assert _does_severity_match_severity_threshold('INFO', 'LOW') is False

    assert _does_severity_match_severity_threshold('LOW', 'LOW') is True
    assert _does_severity_match_severity_threshold('LOW', 'MEDIUM') is False

    assert _does_severity_match_severity_threshold('MEDIUM', 'LOW') is True
    assert _does_severity_match_severity_threshold('MEDIUM', 'MEDIUM') is True
    assert _does_severity_match_severity_threshold('MEDIUM', 'HIGH') is False

    assert _does_severity_match_severity_threshold('HIGH', 'MEDIUM') is True
    assert _does_severity_match_severity_threshold('HIGH', 'HIGH') is True
    assert _does_severity_match_severity_threshold('HIGH', 'CRITICAL') is False

    assert _does_severity_match_severity_threshold('CRITICAL', 'HIGH') is True
    assert _does_severity_match_severity_threshold('CRITICAL', 'CRITICAL') is True

    assert _does_severity_match_severity_threshold('NON_EXISTENT', 'LOW') is True
    assert _does_severity_match_severity_threshold('LOW', 'NON_EXISTENT') is True
