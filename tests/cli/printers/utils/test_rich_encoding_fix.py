"""Tests for Rich encoding fix to handle surrogate characters."""

from io import StringIO
from typing import Any
from unittest.mock import MagicMock

from rich.console import Console

from cycode.cli import consts
from cycode.cli.models import Document
from cycode.cli.printers.rich_printer import RichPrinter
from cycode.cyclient.models import Detection


def create_strict_encoding_console() -> tuple[Console, StringIO]:
    """Create a Console that enforces strict UTF-8 encoding, simulating Windows console behavior.

    When Rich writes to the console, the file object needs to encode strings to bytes.
    With errors='strict' (default for TextIOWrapper), this raises UnicodeEncodeError on surrogates.
    This function simulates that behavior to test the encoding fix.
    """
    buffer = StringIO()

    class StrictEncodingWrapper:
        def __init__(self, file_obj: StringIO) -> None:
            self._file = file_obj

        def write(self, text: str) -> int:
            """Validate encoding before writing to simulate strict encoding behavior."""
            text.encode('utf-8')
            return self._file.write(text)

        def flush(self) -> None:
            self._file.flush()

        def isatty(self) -> bool:
            return False

        def __getattr__(self, name: str) -> Any:
            # Delegate all other attributes to the underlying file
            return getattr(self._file, name)

    strict_file = StrictEncodingWrapper(buffer)
    console = Console(file=strict_file, width=80, force_terminal=False)
    return console, buffer


def test_rich_printer_handles_surrogate_characters_in_violation_card() -> None:
    """Test that RichPrinter._print_violation_card() handles surrogate characters without errors.

    The error occurs in Rich's console._write_buffer() -> write() when console.print() is called.
    On Windows with strict encoding, this raises UnicodeEncodeError on surrogates.
    """
    surrogate_char = chr(0xDC96)
    document_content = 'A' * 1236 + surrogate_char + 'B' * 100
    document = Document(
        path='test.py',
        content=document_content,
        is_git_diff_format=False,
    )

    detection = Detection(
        detection_type_id='test-id',
        type='test-type',
        message='Test message',
        detection_details={
            'description': 'Summary with ' + surrogate_char + ' surrogate character',
            'policy_display_name': 'Test Policy',
            'start_position': 1236,
            'length': 1,
            'line': 0,
        },
        detection_rule_id='test-rule-id',
        severity='Medium',
    )

    mock_ctx = MagicMock()
    mock_ctx.obj = {
        'scan_type': consts.SAST_SCAN_TYPE,
        'show_secret': False,
    }
    mock_ctx.info_name = consts.SAST_SCAN_TYPE

    console, _ = create_strict_encoding_console()
    printer = RichPrinter(mock_ctx, console, console)
    printer._print_violation_card(document, detection, 1, 1)
