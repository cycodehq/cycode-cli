"""Shared transcript helpers for IDE integrations.

Agents keep a session's transcript as JSONL that grows with every turn, images included, so it is read from
the end.
"""

from collections.abc import Iterator
from pathlib import Path


def reverse_readline(path: Path, buf_size: int = 8192) -> Iterator[str]:
    """Yield lines of `path` from end to start without loading the file.

    A transcript can be very large; reading from the tail keeps memory bounded
    since only the most recent entries are wanted.
    """
    with path.open('rb') as f:
        f.seek(0, 2)
        file_size = f.tell()
        if file_size == 0:
            return

        remaining = file_size
        buffer = b''

        while remaining > 0:
            read_size = min(buf_size, remaining)
            remaining -= read_size
            f.seek(remaining)
            chunk = f.read(read_size)
            buffer = chunk + buffer

            while b'\n' in buffer:
                newline_pos = buffer.rfind(b'\n')
                if newline_pos == len(buffer) - 1:
                    newline_pos = buffer.rfind(b'\n', 0, newline_pos)
                    if newline_pos == -1:
                        break
                line = buffer[newline_pos + 1 :]
                buffer = buffer[: newline_pos + 1]
                if line.strip():
                    yield line.decode('utf-8', errors='replace')

        if buffer.strip():
            yield buffer.decode('utf-8', errors='replace')
