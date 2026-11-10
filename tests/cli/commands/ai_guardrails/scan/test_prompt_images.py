"""Tests for prompt image filters and the per-session prompt marks."""

import json
import os
import time
from pathlib import Path

import pytest
from pyfakefs.fake_filesystem import FakeFilesystem

from cycode.cli.apps.ai_guardrails.scan.prompt_images import (
    FIRST_PROMPT_LOOKBACK_SECONDS,
    MAX_PROMPT_IMAGES,
    get_prompt_mark,
    get_prompt_marks_path,
    image_file_name,
    modified_between,
    read_prompt_image,
    save_prompt_mark,
    select_prompt_images,
)
from cycode.cli.consts import FILE_MAX_SIZE_LIMIT_IN_BYTES

PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
JPEG_SIGNATURE = b'\xff\xd8\xff\xe0'


def png(marker: bytes = b'') -> bytes:
    return PNG_SIGNATURE + b'\x00\x00\x00\rIHDR' + marker


def jpeg(marker: bytes = b'') -> bytes:
    return JPEG_SIGNATURE + b'\x00\x10JFIF' + marker


@pytest.fixture(autouse=True)
def _fake_fs(fs: FakeFilesystem) -> FakeFilesystem:
    return fs


# --- prompt marks ---


def test_first_prompt_looks_back_a_fixed_time() -> None:
    now = time.time()

    assert get_prompt_mark('session-1', now) == now - FIRST_PROMPT_LOOKBACK_SECONDS
    # No session id to keep a mark under: every prompt looks back
    assert get_prompt_mark(None, now) == now - FIRST_PROMPT_LOOKBACK_SECONDS


def test_saved_mark_bounds_the_next_prompt_of_that_session_only() -> None:
    now = time.time()
    save_prompt_mark('session-1', now - 30)

    assert get_prompt_mark('session-1', now) == now - 30
    assert get_prompt_mark('session-2', now) == now - FIRST_PROMPT_LOOKBACK_SECONDS


def test_saving_without_a_session_id_writes_nothing() -> None:
    save_prompt_mark(None, time.time())

    assert not get_prompt_marks_path().exists()


def test_mark_after_now_is_clamped() -> None:
    """A mark written before the clock was set back must not hide every new file."""
    now = time.time()
    save_prompt_mark('session-1', now + 3600)

    assert get_prompt_mark('session-1', now) == now


def test_marks_of_sessions_idle_for_a_week_are_pruned_on_save() -> None:
    now = time.time()
    save_prompt_mark('stale', now - 8 * 24 * 60 * 60)
    save_prompt_mark('recent', now - 6 * 24 * 60 * 60)

    save_prompt_mark('current', now)

    marks = json.loads(get_prompt_marks_path().read_text(encoding='utf-8'))
    assert set(marks) == {'recent', 'current'}


@pytest.mark.parametrize('content', ['not json {', '["a list"]', '{"session-1": "not a number"}'])
def test_corrupt_marks_are_moved_aside(fs: FakeFilesystem, content: str) -> None:
    path = get_prompt_marks_path()
    fs.create_file(str(path), contents=content)
    now = time.time()

    assert get_prompt_mark('session-1', now) == now - FIRST_PROMPT_LOOKBACK_SECONDS
    assert not path.exists()
    assert Path(f'{path}.corrupt').exists()

    # The next save starts a fresh file
    save_prompt_mark('session-1', now)
    assert get_prompt_mark('session-1', now + 1) == now


# --- modified_between ---


def test_modified_between_is_half_open_and_oldest_first(fs: FakeFilesystem) -> None:
    # Whole seconds: a fractional mtime may not survive the round trip through nanoseconds exactly
    now = float(int(time.time()))
    since = now - 100
    files = {}
    for name, modified_at in (
        ('newer.png', now - 10),
        ('older.png', now - 50),
        ('at-since.png', since),
        ('before.png', since - 1),
        ('at-until.png', now),
    ):
        files[name] = fs.create_file(f'/attachments/{name}').path
        os.utime(files[name], (modified_at, modified_at))

    selected = modified_between([Path(path) for path in files.values()], since, now)

    # The file stamped exactly `until` belongs to the next prompt, whose window starts there
    assert [path.name for path in selected] == ['at-since.png', 'older.png', 'newer.png']


def test_modified_between_skips_vanished_files() -> None:
    assert modified_between([Path('/attachments/gone.png')], 0, time.time()) == []


# --- filters ---


def test_png_and_jpeg_are_read_by_signature_whatever_their_extension(fs: FakeFilesystem) -> None:
    fs.create_file('/images/shot.png', contents=png())
    fs.create_file('/images/photo.jpeg', contents=jpeg())
    fs.create_file('/images/no-extension', contents=png())
    fs.create_file('/images/fake.png', contents=b'GIF89a not a png')
    fs.create_file('/images/notes.txt', contents='hello')

    assert read_prompt_image('/images/shot.png') == png()
    assert read_prompt_image('/images/photo.jpeg') == jpeg()
    assert read_prompt_image('/images/no-extension') == png()
    assert read_prompt_image('/images/fake.png') is None
    assert read_prompt_image('/images/notes.txt') is None


def test_only_regular_files_within_the_size_limit_are_read(fs: FakeFilesystem) -> None:
    fs.create_dir('/images/a-directory.png')
    fs.create_file('/images/at-limit.png', contents=png().ljust(FILE_MAX_SIZE_LIMIT_IN_BYTES, b'\x00'))
    fs.create_file('/images/over-limit.png', contents=png().ljust(FILE_MAX_SIZE_LIMIT_IN_BYTES + 1, b'\x00'))

    assert read_prompt_image('/images/a-directory.png') is None
    assert read_prompt_image('/images/missing.png') is None
    assert len(read_prompt_image('/images/at-limit.png')) == FILE_MAX_SIZE_LIMIT_IN_BYTES
    assert read_prompt_image('/images/over-limit.png') is None


def test_select_keeps_order_and_drops_non_images(fs: FakeFilesystem) -> None:
    fs.create_file('/images/b.png', contents=png(b'b'))
    fs.create_file('/images/a.jpg', contents=jpeg(b'a'))
    fs.create_file('/images/readme.md', contents='# hi')

    selected = select_prompt_images(['/images/b.png', '/images/readme.md', Path('/images/a.jpg'), '/images/gone.png'])

    assert selected == ['/images/b.png', str(Path('/images/a.jpg'))]


def test_select_keeps_one_path_per_content(fs: FakeFilesystem) -> None:
    """VS Code saves a paste when it is made and copies it again on send: one image, two files."""
    fs.create_file('/sent/image.png', contents=png(b'same'))
    fs.create_file('/pasted/image-1784034535752.png', contents=png(b'same'))
    fs.create_file('/pasted/image-1784034535999.png', contents=png(b'other'))

    selected = select_prompt_images(
        ['/sent/image.png', '/pasted/image-1784034535752.png', '/pasted/image-1784034535999.png']
    )

    assert selected == ['/sent/image.png', '/pasted/image-1784034535999.png']


def test_select_caps_the_number_of_images(fs: FakeFilesystem) -> None:
    paths = []
    for index in range(MAX_PROMPT_IMAGES + 2):
        paths.append(f'/images/{index}.png')
        fs.create_file(paths[-1], contents=png(str(index).encode()))
    # Same content as 0.png: the copy is listed first, and 0.png then takes no slot under the cap
    fs.create_file('/images/copy.png', contents=png(b'0'))

    selected = select_prompt_images(['/images/copy.png', *paths])

    assert selected == ['/images/copy.png', *paths[1:MAX_PROMPT_IMAGES]]
    assert len(selected) == MAX_PROMPT_IMAGES


def test_image_file_name_names_the_actual_format() -> None:
    assert image_file_name('/x/shot.png', png()) == 'shot.png'
    assert image_file_name('/x/photo.JPEG', jpeg()) == 'photo.JPEG'
    assert image_file_name('/x/photo.jpg', jpeg()) == 'photo.jpg'
    # The server picks images by extension as well as signature, so a missing or wrong one is completed
    assert image_file_name('/x/screenshot', png()) == 'screenshot.png'
    assert image_file_name('/x/actually-a-jpeg.png', jpeg()) == 'actually-a-jpeg.png.jpg'
