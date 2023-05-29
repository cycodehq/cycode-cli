from cycode.cli.utils.machine_id import _get_hmac_hex, machine_id, protected_machine_id  # noqa
from cycode.cyclient import logger

_APP_ID = 'TestsCycodeCLI'


def test_hmac_hex():
    key = 'ee8cd7bb-b427-4f56-ab0b-e02271cfce5c'
    msg = 'e9913617-37ea-4ade-bbf9-58e3bf6c7937'
    hmac_hex = _get_hmac_hex(key, msg)

    expected_hmac_hex = '4dd8f70c07dd2b659c77a784169e9625960af8d598461a573522725a2be08f49'

    assert expected_hmac_hex == hmac_hex


def test_machine_id_presented():
    mid = machine_id()

    logger.info(f'Machine ID: {mid}')

    assert mid
    assert isinstance(mid, str)


def test_protected_machine_id_presented():
    mid = protected_machine_id(_APP_ID)

    logger.info(f'Protected Machine ID: {mid}')

    assert mid
    assert isinstance(mid, str)


def test_machine_id_cache():
    calls_count = 100

    machine_id.cache_clear()  # invalidate cache from prev tests

    for _ in range(calls_count):
        machine_id()

    expected_misses = 1     # the first call calculates the value
    expected_hits = calls_count - expected_misses

    cache_info = machine_id.cache_info()
    assert cache_info.hits == expected_hits
    assert cache_info.misses == expected_misses


def test_protected_machine_id_cache():
    calls_count = 100

    protected_machine_id.cache_clear()  # invalidate cache from prev tests

    for _ in range(calls_count):
        protected_machine_id(_APP_ID)

    expected_misses = 1     # the first call calculates the value
    expected_hits = calls_count - expected_misses

    cache_info = protected_machine_id.cache_info()
    assert cache_info.hits == expected_hits
    assert cache_info.misses == expected_misses
