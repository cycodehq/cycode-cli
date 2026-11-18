"""Images attached to an AI prompt, scanned for secrets along with its text.

Some IDEs (GitHub Copilot, Claude Code) save a prompt's attachments to disk before its hook runs, yet never name them
in the hook payload. The IDE integration finds the candidates (``IDE.collect_prompt_images``); this module holds what
is IDE-agnostic about them: `@path` mentions, the filters every candidate passes, and the per-session prompt marks that
turn "files saved for this prompt" into "files saved since the session's previous prompt".

A session's first prompt looks back a fixed time rather than to session start: VS Code fires SessionStart together
with the first prompt, after its attachments were already saved.
"""

import hashlib
import json
import os
import re
import stat
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from cycode.cli.consts import CYCODE_CONFIGURATION_DIRECTORY, FILE_MAX_SIZE_LIMIT_IN_BYTES
from cycode.cli.utils.path_utils import atomic_write_text, quarantine_corrupt_file
from cycode.logger import get_logger

logger = get_logger('AI Guardrails')

PROMPT_MARKS_FILE_NAME = 'ai-guardrails-prompt-marks.json'

# Each image adds to the scan's time, which the IDE's hook timeout bounds
MAX_PROMPT_IMAGES = 5

# Covers attachments saved a while before the prompt was sent
FIRST_PROMPT_LOOKBACK_SECONDS = 600

# A pasted or dragged image's placeholder in the prompt text, as Claude Code and Codex write it
_IMAGE_CHIP_PATTERN = re.compile(r'\[Image #(\d+)\]')

# A session idle this long loses its mark; if it comes back, its next prompt falls back to the lookback
_MARK_RETENTION_SECONDS = 7 * 24 * 60 * 60

# The image formats sent for scanning, by signature (a file's own extension can be wrong or missing), with the
# extensions that name each one
_IMAGE_FORMATS = (
    (b'\x89PNG\r\n\x1a\n', ('.png',)),
    (b'\xff\xd8\xff', ('.jpg', '.jpeg')),
)
_SIGNATURE_LENGTH = max(len(signature) for signature, _ in _IMAGE_FORMATS)

# An `@path` mention as typed in a prompt: quoted, with backslash-escaped spaces (a file dragged into a terminal), or
# plain up to the next whitespace. Never mid-word, so an email address is not a mention. A lookahead, so every `@` is
# read on its own: a quote left open must not swallow the mentions after it, and a quoted path never spans lines.
_MENTION_PATTERN = re.compile(r'(?<!\S)@(?=("[^"\n]+"|\'[^\'\n]+\'|(?:\\ |\S)+))')
_MENTION_TRAILING_PUNCTUATION = '.,;:!?)]}'


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


def mentioned_files(prompt: str, cwd: str | None) -> list[Path]:
    """Existing files named by `@` mentions, resolved against the hook's cwd."""
    base = Path(cwd) if cwd else Path()
    files = []
    for match in _MENTION_PATTERN.finditer(prompt):
        token = match.group(1)
        if len(token) > 1 and token[0] == token[-1] and token[0] in '"\'':
            spellings = [token[1:-1]]
        else:
            if os.sep == '/':
                token = token.replace('\\ ', ' ')
            # The mention may end a sentence ("look at @shot.png.")
            spellings = [token, token.rstrip(_MENTION_TRAILING_PUNCTUATION)]
        for spelling in spellings:
            path = base / os.path.expanduser(spelling)
            if os.path.isfile(path):
                files.append(path)
                break
    return files


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


@dataclass(frozen=True)
class PromptImage:
    """An image attached to a prompt, read once when it is collected: where it was, and its bytes."""

    path: str
    content: bytes

    @property
    def file_name(self) -> str:
        """The file's name, plus the extension of its actual format when its own extension doesn't name it."""
        name = os.path.basename(self.path)
        extensions = _image_extensions(self.content)
        if extensions and os.path.splitext(name)[1].lower() not in extensions:
            name += extensions[0]
        return name


def select_prompt_images(candidates: Iterable[str | os.PathLike]) -> list[PromptImage]:
    """The candidates to scan, in order: scannable images (see read_prompt_image), each content once, at most
    MAX_PROMPT_IMAGES.

    Once per content because the same image can be attached twice, for example pasted and also mentioned by path.
    """
    selected: list[PromptImage] = []
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
        selected.append(PromptImage(path=str(candidate), content=content))

    return selected


def image_chips(prompt: str) -> list[str]:
    """The numbers of the prompt's ``[Image #N]`` placeholders, as written and in the prompt's order."""
    return _IMAGE_CHIP_PATTERN.findall(prompt)


def collect_since_prompt_mark(
    session_id: str | None, gather: Callable[[float, float], Iterable[str | os.PathLike]]
) -> list[PromptImage]:
    """The images ``gather`` finds in the session's window ``[since, now)``, then the session's mark moves to now.

    The mark moves only after the images are selected; moving it first would leave this prompt's files to no one.
    """
    now = time.time()
    since = get_prompt_mark(session_id, now)
    images = select_prompt_images(gather(since, now))
    save_prompt_mark(session_id, now)
    logger.debug('Collected prompt images, %s', {'images_count': len(images), 'since': since})
    return images
