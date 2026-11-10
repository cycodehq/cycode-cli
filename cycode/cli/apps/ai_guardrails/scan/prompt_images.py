"""Images attached to an AI prompt, scanned for secrets along with its text.

Some IDEs (GitHub Copilot) save a prompt's attachments to disk before its hook runs, yet never name them in the
hook payload. The IDE integration finds the candidates (``IDE.collect_prompt_images``); this module holds what is
IDE-agnostic about them: the filters every candidate passes, and the per-session prompt marks that turn "files saved
for this prompt" into "files saved since the session's previous prompt".

A session's first prompt looks back a fixed time rather than to session start: VS Code fires SessionStart together
with the first prompt, after its attachments were already saved.
"""

import hashlib
import json
import os
import stat
from collections.abc import Iterable
from pathlib import Path

from cycode.cli.consts import CYCODE_CONFIGURATION_DIRECTORY, FILE_MAX_SIZE_LIMIT_IN_BYTES
from cycode.cli.utils.path_utils import atomic_write_text, quarantine_corrupt_file
from cycode.logger import get_logger

logger = get_logger('AI Guardrails')

PROMPT_MARKS_FILE_NAME = 'ai-guardrails-prompt-marks.json'

# Each image is read by OCR on the server, within the IDE's hook timeout
MAX_PROMPT_IMAGES = 5

# Covers a paste made a while before sending, without reaching far into other chats' images
FIRST_PROMPT_LOOKBACK_SECONDS = 600

# A session idle this long loses its mark; if it comes back, its next prompt falls back to the lookback
_MARK_RETENTION_SECONDS = 7 * 24 * 60 * 60

# The formats the server reads text out of, by signature (a file's own extension can be wrong or missing), with the
# extensions that name each one
_IMAGE_FORMATS = (
    (b'\x89PNG\r\n\x1a\n', ('.png',)),
    (b'\xff\xd8\xff', ('.jpg', '.jpeg')),
)
_SIGNATURE_LENGTH = max(len(signature) for signature, _ in _IMAGE_FORMATS)


def get_prompt_marks_path() -> Path:
    return Path.home() / CYCODE_CONFIGURATION_DIRECTORY / PROMPT_MARKS_FILE_NAME


def _load_marks() -> dict[str, float]:
    """``{session_id: timestamp}``; empty when the file is absent, or corrupt (then it is moved aside)."""
    path = get_prompt_marks_path()
    if not path.exists():
        return {}

    try:
        with open(path, encoding='UTF-8') as file:
            marks = json.load(file)
        if not isinstance(marks, dict):
            raise TypeError('prompt marks are not an object')
        return {str(session_id): float(timestamp) for session_id, timestamp in marks.items()}
    except Exception as e:
        logger.warning('Prompt marks file is corrupt and will be moved aside', exc_info=e)
        quarantine_corrupt_file(str(path))
        return {}


def get_prompt_mark(session_id: str | None, now: float) -> float:
    """Where a prompt's attachments start: the session's previous prompt, or the first-prompt lookback."""
    mark = _load_marks().get(session_id) if session_id else None
    if mark is None:
        return now - FIRST_PROMPT_LOOKBACK_SECONDS
    # A mark from before the clock was set back must not hide every new file
    return min(mark, now)


def save_prompt_mark(session_id: str | None, now: float) -> None:
    """Move the session's mark to ``now`` and drop the marks of long-idle sessions. Never raises.

    Unlocked read-modify-write: two sessions prompting at the same moment may lose one update, which only sends that
    session's next prompt back to the lookback. The atomic write keeps the file whole.
    """
    if not session_id:
        return

    marks = _load_marks()
    marks[session_id] = now
    cutoff = now - _MARK_RETENTION_SECONDS
    marks = {key: timestamp for key, timestamp in marks.items() if timestamp >= cutoff}

    path = get_prompt_marks_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(str(path), json.dumps(marks))
    except Exception as e:
        logger.debug('Failed to save prompt marks', exc_info=e)


def modified_between(paths: Iterable[Path], since: float, until: float) -> list[Path]:
    """The paths last modified in ``[since, until)``, oldest first (the order they were attached in).

    Half-open so that each file belongs to exactly one prompt: a file saved while this prompt's images are being
    collected is left to the next prompt, whose window starts where this one ends.
    """
    dated = []
    for path in paths:
        try:
            modified_at = path.stat().st_mtime
        except OSError:
            continue
        if since <= modified_at < until:
            dated.append((modified_at, path))
    return [path for _, path in sorted(dated, key=lambda item: item[0])]


def _image_extensions(content: bytes) -> tuple[str, ...]:
    return next((extensions for signature, extensions in _IMAGE_FORMATS if content.startswith(signature)), ())


def read_prompt_image(path: str | os.PathLike) -> bytes | None:
    """The bytes of a scannable image - a regular PNG or JPEG file within the size limit - or None.

    Regular files only, checked before opening: an `@` mention can name a FIFO or a device, and reading one would
    hang the hook. The signature is read first, so a mentioned source file is never read in full.
    """
    try:
        file_stat = os.stat(path)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > FILE_MAX_SIZE_LIMIT_IN_BYTES:
            return None
        with open(path, 'rb') as file:
            head = file.read(_SIGNATURE_LENGTH)
            if not _image_extensions(head):
                return None
            # One byte past the limit tells a file that grew since the stat
            content = head + file.read(FILE_MAX_SIZE_LIMIT_IN_BYTES + 1 - len(head))
    except (OSError, ValueError) as e:
        logger.debug('Failed to read a prompt image candidate, %s', {'path': str(path)}, exc_info=e)
        return None

    return content if len(content) <= FILE_MAX_SIZE_LIMIT_IN_BYTES else None


def image_file_name(path: str, content: bytes) -> str:
    """The file's name, plus the extension of its actual format when its own extension doesn't name that format."""
    name = os.path.basename(path)
    extensions = _image_extensions(content)
    if extensions and os.path.splitext(name)[1].lower() not in extensions:
        name += extensions[0]
    return name


def select_prompt_images(candidates: Iterable[str | os.PathLike]) -> list[str]:
    """The candidates to scan, in order: scannable images (see read_prompt_image), each content once, at most
    MAX_PROMPT_IMAGES.

    Once per content because one attachment can be on disk twice: VS Code saves a paste when it is made and copies
    it again when the prompt is sent.
    """
    selected: list[str] = []
    seen_digests: set[str] = set()
    for candidate in candidates:
        content = read_prompt_image(candidate)
        if content is None:
            continue

        digest = hashlib.sha256(content).hexdigest()
        if digest in seen_digests:
            continue

        if len(selected) == MAX_PROMPT_IMAGES:
            logger.debug('More images than a prompt scans; skipping the rest, %s', {'max_images': MAX_PROMPT_IMAGES})
            break

        seen_digests.add(digest)
        selected.append(str(candidate))

    return selected
