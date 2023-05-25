from cycode.cli.utils.machine_id import _get_hmac_hex, machine_id, protected_machine_id  # noqa

_APP_ID = 'TestsCycodeCLI'


def test_hmac_hex():
    key = 'ee8cd7bb-b427-4f56-ab0b-e02271cfce5c'
    msg = 'e9913617-37ea-4ade-bbf9-58e3bf6c7937'
    hmac_hex = _get_hmac_hex(key, msg)

    expected_hmac_hex = '4dd8f70c07dd2b659c77a784169e9625960af8d598461a573522725a2be08f49'

    assert expected_hmac_hex == hmac_hex


def test_machine_id_presented():
    mid = machine_id()

    assert str
    assert str is type(mid)


def test_protected_machine_id_presented():
    mid = protected_machine_id(_APP_ID)

    assert str
    assert str is type(mid)
