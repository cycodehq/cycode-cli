from cycode.cli.cli_types import SeverityOption


def test_get_member_weight() -> None:
    assert SeverityOption.get_member_weight('INFO') == 0
    assert SeverityOption.get_member_weight('LOW') == 1
    assert SeverityOption.get_member_weight('MEDIUM') == 2
    assert SeverityOption.get_member_weight('HIGH') == 3
    assert SeverityOption.get_member_weight('CRITICAL') == 4

    assert SeverityOption.get_member_weight('NON_EXISTENT') == -1
