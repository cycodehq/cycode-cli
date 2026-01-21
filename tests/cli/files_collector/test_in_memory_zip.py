"""Tests for InMemoryZip class, specifically for handling surrogate characters and encoding issues."""

import zipfile
from io import BytesIO

from cycode.cli.files_collector.models.in_memory_zip import InMemoryZip


def test_append_with_surrogate_characters() -> None:
    """Test that surrogate characters are handled gracefully without raising encoding errors."""
    # Surrogate characters (U+D800 to U+DFFF) cannot be encoded to UTF-8 directly
    zip_file = InMemoryZip()
    content = 'Normal text \udc96 more text'

    # Should not raise UnicodeEncodeError
    zip_file.append('test.txt', None, content)
    zip_file.close()

    # Verify the ZIP was created successfully
    zip_data = zip_file.read()
    assert len(zip_data) > 0

    # Verify we can read it back and the surrogate was replaced
    with zipfile.ZipFile(BytesIO(zip_data), 'r') as zf:
        extracted = zf.read('test.txt').decode('utf-8')
        assert 'Normal text' in extracted
        assert 'more text' in extracted
        # The surrogate should have been replaced with the replacement character
        assert '\udc96' not in extracted
