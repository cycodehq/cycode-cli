import pytest

from cycode.cli.utils.binary_utils import is_binary_string


@pytest.mark.parametrize(
    ('data', 'expected'),
    [
        # Empty / None-ish
        (b'', False),
        (None, False),
        # Plain ASCII text
        (b'Hello, world!', False),
        (b'print("hello")\nfor i in range(10):\n    pass\n', False),
        # Whitespace-heavy text (tabs, newlines) is not binary
        (b'\t\t\n\n\r\n  some text\n', False),
        # UTF-8 multibyte text (accented, CJK, emoji)
        ('café résumé naïve'.encode(), False),
        ('日本語テキスト'.encode(), False),
        ('🎉🚀💻'.encode(), False),
        # BOM-marked UTF-16/32 text is not binary
        ('\ufeffHello UTF-16'.encode('utf-16-le'), False),
        ('\ufeffHello UTF-16'.encode('utf-16-be'), False),
        ('\ufeffHello UTF-32'.encode('utf-32-le'), False),
        ('\ufeffHello UTF-32'.encode('utf-32-be'), False),
        # Null bytes → binary
        (b'\x00', True),
        (b'hello\x00world', True),
        (b'\x00\x01\x02\x03', True),
        # 0xff in otherwise normal data → binary
        (b'hello\xffworld', True),
        # Mostly control chars + invalid UTF-8 → binary
        (b'\x01\x02\x03\x04\x05\x06\x07\x0e\x0f\x10' * 10 + b'\x80', True),
        # Real binary format headers
        (b'\x89PNG\r\n\x1a\n' + b'\x00' * 100, True),
        (b'\x7fELF' + b'\x00' * 100, True),
        # DS_Store-like: null-byte-heavy valid UTF-8 → still binary
        (b'\x00\x00\x00\x01Bud1' + b'\x00' * 100, True),
    ],
)
def test_is_binary_string(data: bytes, expected: bool) -> None:
    assert is_binary_string(data) is expected
