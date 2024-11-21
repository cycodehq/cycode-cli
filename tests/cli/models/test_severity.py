from cycode.cli.models import Severity


def test_try_get_value():
    assert Severity.try_get_value('info') == -1
    assert Severity.try_get_value('iNfO') == -1

    assert Severity.try_get_value('INFO') == -1
    assert Severity.try_get_value('LOW') == 0
    assert Severity.try_get_value('MEDIUM') == 1
    assert Severity.try_get_value('HIGH') == 2
    assert Severity.try_get_value('CRITICAL') == 3

    assert Severity.try_get_value('NON_EXISTENT') is None


def test_get_member_weight():
    assert Severity.get_member_weight('INFO') == -1
    assert Severity.get_member_weight('LOW') == 0
    assert Severity.get_member_weight('MEDIUM') == 1
    assert Severity.get_member_weight('HIGH') == 2
    assert Severity.get_member_weight('CRITICAL') == 3

    assert Severity.get_member_weight('NON_EXISTENT') == -2
