_CONTROL_CHARS = b'\n\r\t\f\b'
_PRINTABLE_ASCII = _CONTROL_CHARS + bytes(range(32, 127))
_PRINTABLE_HIGH_ASCII = bytes(range(127, 256))

# BOM signatures for encodings that legitimately contain null bytes
_BOM_ENCODINGS = (
    (b'\xff\xfe\x00\x00', 'utf-32-le'),
    (b'\x00\x00\xfe\xff', 'utf-32-be'),
    (b'\xff\xfe', 'utf-16-le'),
    (b'\xfe\xff', 'utf-16-be'),
)


def _has_bom_encoding(bytes_to_check: bytes) -> bool:
    """Check if bytes start with a BOM and can be decoded as that encoding."""
    for bom, encoding in _BOM_ENCODINGS:
        if bytes_to_check.startswith(bom):
            try:
                bytes_to_check.decode(encoding)
                return True
            except (UnicodeDecodeError, LookupError):
                pass
    return False


def _is_decodable_as_utf8(bytes_to_check: bytes) -> bool:
    """Try to decode bytes as UTF-8."""
    try:
        bytes_to_check.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


def is_binary_string(bytes_to_check: bytes) -> bool:
    """Check if a chunk of bytes appears to be binary content.

    Uses a simplified version of the Perl detection algorithm, matching
    the structure of binaryornot's is_binary_string.
    """
    if not bytes_to_check:
        return False

    # Binary if control chars are > 30% of the string
    low_chars = bytes_to_check.translate(None, _PRINTABLE_ASCII)
    nontext_ratio1 = len(low_chars) / len(bytes_to_check)

    # Binary if high ASCII chars are < 5% of the string
    high_chars = bytes_to_check.translate(None, _PRINTABLE_HIGH_ASCII)
    nontext_ratio2 = len(high_chars) / len(bytes_to_check)

    is_likely_binary = (nontext_ratio1 > 0.3 and nontext_ratio2 < 0.05) or (
        nontext_ratio1 > 0.8 and nontext_ratio2 > 0.8
    )

    # BOM-marked UTF-16/32 files legitimately contain null bytes.
    # Check this first so they aren't misdetected as binary.
    if _has_bom_encoding(bytes_to_check):
        return False

    has_null_or_xff = b'\x00' in bytes_to_check or b'\xff' in bytes_to_check

    if is_likely_binary:
        # Only let UTF-8 rescue data that doesn't contain null bytes.
        # Null bytes are valid UTF-8 but almost never appear in real text files,
        # whereas binary formats (e.g. .DS_Store) are full of them.
        if has_null_or_xff:
            return True
        return not _is_decodable_as_utf8(bytes_to_check)

    # Null bytes or 0xff in otherwise normal-looking data indicate binary
    return bool(has_null_or_xff)
