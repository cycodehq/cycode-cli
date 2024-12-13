# Copyright (C) 2017 Jelmer Vernooij <jelmer@jelmer.uk>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Modified (rewritten to pytest + pyfakefs) from https://github.com/jelmer/dulwich/blob/master/tests/test_ignore.py

import os
import re
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from cycode.cli.utils.ignore_utils import (
    IgnoreFilter,
    IgnoreFilterManager,
    Pattern,
    match_pattern,
    read_ignore_patterns,
    translate,
)

if TYPE_CHECKING:
    from pyfakefs.fake_filesystem import FakeFilesystem

POSITIVE_MATCH_TESTS = [
    (b'foo.c', b'*.c'),
    (b'.c', b'*.c'),
    (b'foo/foo.c', b'*.c'),
    (b'foo/foo.c', b'foo.c'),
    (b'foo.c', b'/*.c'),
    (b'foo.c', b'/foo.c'),
    (b'foo.c', b'foo.c'),
    (b'foo.c', b'foo.[ch]'),
    (b'foo/bar/bla.c', b'foo/**'),
    (b'foo/bar/bla/blie.c', b'foo/**/blie.c'),
    (b'foo/bar/bla.c', b'**/bla.c'),
    (b'bla.c', b'**/bla.c'),
    (b'foo/bar', b'foo/**/bar'),
    (b'foo/bla/bar', b'foo/**/bar'),
    (b'foo/bar/', b'bar/'),
    (b'foo/bar/', b'bar'),
    (b'foo/bar/something', b'foo/bar/*'),
]

NEGATIVE_MATCH_TESTS = [
    (b'foo.c', b'foo.[dh]'),
    (b'foo/foo.c', b'/foo.c'),
    (b'foo/foo.c', b'/*.c'),
    (b'foo/bar/', b'/bar/'),
    (b'foo/bar/', b'foo/bar/*'),
    (b'foo/bar', b'foo?bar'),
]

TRANSLATE_TESTS = [
    (b'*.c', b'(?ms)(.*/)?[^/]*\\.c/?\\Z'),
    (b'foo.c', b'(?ms)(.*/)?foo\\.c/?\\Z'),
    (b'/*.c', b'(?ms)[^/]*\\.c/?\\Z'),
    (b'/foo.c', b'(?ms)foo\\.c/?\\Z'),
    (b'foo.c', b'(?ms)(.*/)?foo\\.c/?\\Z'),
    (b'foo.[ch]', b'(?ms)(.*/)?foo\\.[ch]/?\\Z'),
    (b'bar/', b'(?ms)(.*/)?bar\\/\\Z'),
    (b'foo/**', b'(?ms)foo(/.*)?/?\\Z'),
    (b'foo/**/blie.c', b'(?ms)foo(/.*)?\\/blie\\.c/?\\Z'),
    (b'**/bla.c', b'(?ms)(.*/)?bla\\.c/?\\Z'),
    (b'foo/**/bar', b'(?ms)foo(/.*)?\\/bar/?\\Z'),
    (b'foo/bar/*', b'(?ms)foo\\/bar\\/[^/]+/?\\Z'),
    (b'/foo\\[bar\\]', b'(?ms)foo\\[bar\\]/?\\Z'),
    (b'/foo[bar]', b'(?ms)foo[bar]/?\\Z'),
    (b'/foo[0-9]', b'(?ms)foo[0-9]/?\\Z'),
]


@pytest.mark.usefixtures('fs')
class TestIgnoreFiles:
    def test_translate(self) -> None:
        for pattern, regex in TRANSLATE_TESTS:
            if re.escape(b'/') == b'/':
                regex = regex.replace(b'\\/', b'/')
            assert (
                translate(pattern) == regex
            ), f'orig pattern: {pattern!r}, regex: {translate(pattern)!r}, expected: {regex!r}'

    def test_read_file(self) -> None:
        f = BytesIO(
            b"""
# a comment
\x20\x20
# and an empty line:

\\#not a comment
!negative
with trailing whitespace 
with escaped trailing whitespace\\ 
"""  # noqa: W291 (Trailing whitespace)
        )
        assert list(read_ignore_patterns(f)) == [
            b'\\#not a comment',
            b'!negative',
            b'with trailing whitespace',
            b'with escaped trailing whitespace ',
        ]

    def test_match_patterns_positive(self) -> None:
        for path, pattern in POSITIVE_MATCH_TESTS:
            assert match_pattern(path, pattern), f'path: {path!r}, pattern: {pattern!r}'

    def test_match_patterns_negative(self) -> None:
        for path, pattern in NEGATIVE_MATCH_TESTS:
            assert not match_pattern(path, pattern), f'path: {path!r}, pattern: {pattern!r}'

    def test_ignore_filter_inclusion(self) -> None:
        ignore_filter = IgnoreFilter([b'a.c', b'b.c'])
        assert ignore_filter.is_ignored(b'a.c')
        assert ignore_filter.is_ignored(b'c.c') is None
        assert list(ignore_filter.find_matching(b'a.c')) == [Pattern(b'a.c')]
        assert list(ignore_filter.find_matching(b'c.c')) == []

    def test_ignore_filter_exclusion(self) -> None:
        ignore_filter = IgnoreFilter([b'a.c', b'b.c', b'!c.c'])
        assert not ignore_filter.is_ignored(b'c.c')
        assert ignore_filter.is_ignored(b'd.c') is None
        assert list(ignore_filter.find_matching(b'c.c')) == [Pattern(b'!c.c')]
        assert list(ignore_filter.find_matching(b'd.c')) == []

    def test_ignore_filter_manager(self, fs: 'FakeFilesystem') -> None:
        # Prepare sample ignore patterns
        fs.create_file('/path/to/repo/.gitignore', contents=b'/foo/bar\n/dir2\n/dir3/\n')
        fs.create_file('/path/to/repo/dir/.gitignore', contents=b'/blie\n')
        fs.create_file('/path/to/repo/.git/info/exclude', contents=b'/excluded\n')

        m = IgnoreFilterManager.build('/path/to/repo')

        assert m.is_ignored('dir/blie')
        assert m.is_ignored(os.path.join('dir', 'bloe')) is None
        assert m.is_ignored('dir') is None
        assert m.is_ignored(os.path.join('foo', 'bar'))
        assert m.is_ignored(os.path.join('excluded'))
        assert m.is_ignored(os.path.join('dir2', 'fileinignoreddir'))
        assert not m.is_ignored('dir3')
        assert m.is_ignored('dir3/')
        assert m.is_ignored('dir3/bla')

    def test_nested_gitignores(self, fs: 'FakeFilesystem') -> None:
        fs.create_file('/path/to/repo/.gitignore', contents=b'/*\n!/foo\n')
        fs.create_file('/path/to/repo/foo/.gitignore', contents=b'/bar\n')
        fs.create_file('/path/to/repo/foo/bar', contents=b'IGNORED')

        m = IgnoreFilterManager.build('/path/to/repo')
        assert m.is_ignored('foo/bar')

    def test_load_ignore_ignore_case(self, fs: 'FakeFilesystem') -> None:
        fs.create_file('/path/to/repo/.gitignore', contents=b'/foo/bar\n/dir\n')

        m = IgnoreFilterManager.build('/path/to/repo', ignore_case=True)
        assert m.is_ignored(os.path.join('dir', 'blie'))
        assert m.is_ignored(os.path.join('DIR', 'blie'))

    def test_ignored_contents(self, fs: 'FakeFilesystem') -> None:
        fs.create_file('/path/to/repo/.gitignore', contents=b'a/*\n!a/*.txt\n')

        m = IgnoreFilterManager.build('/path/to/repo')
        assert m.is_ignored('a') is None
        assert m.is_ignored('a/') is None
        assert not m.is_ignored('a/b.txt')
        assert m.is_ignored('a/c.dat')
