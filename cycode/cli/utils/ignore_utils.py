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

# Modified from https://github.com/dulwich/dulwich/blob/master/dulwich/ignore.py

# Copyright 2020 Ben Kehoe
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Modified from https://github.com/benkehoe/ignorelib/blob/main/ignorelib.py

"""Parsing of ignore files according to gitignore rules.

For details for the matching rules, see https://git-scm.com/docs/gitignore
"""

import os.path
import re
from typing import (
    BinaryIO,
    Iterable,
    List,
    Optional,
    TYPE_CHECKING,
    Dict,
    Union,
)

def _translate_segment(segment: bytes) -> bytes:
    if segment == b"*":
        return b'[^/]+'
    res = b""
    i, n = 0, len(segment)
    while i < n:
        c = segment[i:i+1]
        i = i+1
        if c == b'*':
            res += b'[^/]*'
        elif c == b'?':
            res += b'[^/]'
        elif c == b'[':
            j = i
            if j < n and segment[j:j+1] == b'!':
                j = j+1
            if j < n and segment[j:j+1] == b']':
                j = j+1
            while j < n and segment[j:j+1] != b']':
                j = j+1
            if j >= n:
                res += b'\\['
            else:
                stuff = segment[i:j].replace(b'\\', b'\\\\')
                i = j+1
                if stuff.startswith(b'!'):
                    stuff = b'^' + stuff[1:]
                elif stuff.startswith(b'^'):
                    stuff = b'\\' + stuff
                res += b'[' + stuff + b']'
        else:
            res += re.escape(c)
    return res


def translate(pat: bytes) -> bytes:
    """Translate a shell PATTERN to a regular expression.

    There is no way to quote meta-characters.

    Originally copied from fnmatch in Python 2.7, but modified for Dulwich
    to cope with features in Git ignore patterns.
    """

    res = b'(?ms)'

    if b'/' not in pat[:-1]:
        # If there's no slash, this is a filename-based match
        res += b'(.*/)?'

    if pat.startswith(b'**/'):
        # Leading **/
        pat = pat[2:]
        res += b'(.*/)?'

    if pat.startswith(b'/'):
        pat = pat[1:]

    for i, segment in enumerate(pat.split(b'/')):
        if segment == b'**':
            res += b'(/.*)?'
            continue
        else:
            res += ((re.escape(b'/') if i > 0 else b'') +
                    _translate_segment(segment))

    if not pat.endswith(b'/'):
        res += b'/?'

    return res + b'\\Z'


def read_ignore_patterns(f: BinaryIO) -> Iterable[bytes]:
    """Read a git ignore file.

    Args:
      f: File-like object to read from
    Returns: List of patterns
    """

    for line in f:
        line = line.rstrip(b"\r\n")

        # Ignore blank lines, they're used for readability.
        if not line:
            continue

        if line.startswith(b'#'):
            # Comment
            continue

        # Trailing spaces are ignored unless they are quoted with a backslash.
        while line.endswith(b' ') and not line.endswith(b'\\ '):
            line = line[:-1]
        line = line.replace(b'\\ ', b' ')

        yield line


def match_pattern(
        path: bytes, pattern: bytes, ignore_case: bool = False) -> bool:
    """Match a gitignore-style pattern against a path.

    Args:
      path: Path to match
      pattern: Pattern to match
      ignore_case: Whether to do case-sensitive matching
    Returns:
      bool indicating whether the pattern matched
    """
    return Pattern(pattern, ignore_case).match(path)


class Pattern(object):
    """A single ignore pattern."""

    def __init__(self, pattern: bytes, ignore_case: bool = False):
        self.pattern = pattern
        self.ignore_case = ignore_case
        if pattern[0:1] == b'!':
            self.is_exclude = False
            pattern = pattern[1:]
        else:
            if pattern[0:1] == b'\\':
                pattern = pattern[1:]
            self.is_exclude = True
        flags = 0
        if self.ignore_case:
            flags = re.IGNORECASE
        self._re = re.compile(translate(pattern), flags)

    def __bytes__(self) -> bytes:
        return self.pattern

    def __str__(self) -> str:
        return os.fsdecode(self.pattern)

    def __eq__(self, other: object) -> bool:
        return (isinstance(other, type(self)) and
                self.pattern == other.pattern and
                self.ignore_case == other.ignore_case)

    def __repr__(self) -> str:
        return "%s(%r, %r)" % (
            type(self).__name__, self.pattern, self.ignore_case)

    def match(self, path: bytes) -> bool:
        """Try to match a path against this ignore pattern.

        Args:
          path: Path to match (relative to ignore location)
        Returns: boolean
        """
        return bool(self._re.match(path))


class IgnoreFilter(object):

    def __init__(self, patterns: Iterable[Union[str, bytes]], ignore_case: bool = False,
                 path=None):
        if hasattr(path, '__fspath__'):
            path = path.__fspath__()
        self._patterns = []  # type: List[Pattern]
        self._ignore_case = ignore_case
        self._path = path
        for pattern in patterns:
            self.append_pattern(pattern)

    def to_dict(self):
        d = {
            "patterns": [str(p) for p in self._patterns],
            "ignore_case": self._ignore_case,
        }
        path = getattr(self, '_path', None)
        if path:
            d["path"] = path
        return d

    def append_pattern(self, pattern: Union[str, bytes]) -> None:
        """Add a pattern to the set."""
        if isinstance(pattern, str):
            pattern = bytes(pattern, 'utf-8')
        self._patterns.append(Pattern(pattern, self._ignore_case))

    def find_matching(self, path: Union[bytes, str]) -> Iterable[Pattern]:
        """Yield all matching patterns for path.

        Args:
          path: Path to match
        Returns:
          Iterator over iterators
        """
        if not isinstance(path, bytes):
            path = os.fsencode(path)
        for pattern in self._patterns:
            if pattern.match(path):
                yield pattern

    def is_ignored(self, path: Union[bytes, str]) -> Optional[bool]:
        """Check whether a path is ignored.

        For directories, include a trailing slash.

        Returns: status is None if file is not mentioned, True if it is
            included, False if it is explicitly excluded.
        """
        if hasattr(path, '__fspath__'):
            path = path.__fspath__()
        status = None
        for pattern in self.find_matching(path):
            status = pattern.is_exclude
        return status

    @classmethod
    def from_path(cls, path, ignore_case: bool = False) -> 'IgnoreFilter':
        if hasattr(path, '__fspath__'):
            path = path.__fspath__()
        with open(path, 'rb') as f:
            return cls(read_ignore_patterns(f), ignore_case, path=path)

    def __repr__(self) -> str:
        path = getattr(self, '_path', None)
        if path is not None:
            return "%s.from_path(%r)" % (
                type(self).__name__, path)
        else:
            return "<%s>" % (type(self).__name__)


class IgnoreFilterStack(object):
    """Check for ignore status in multiple filters."""

    def __init__(self, filters):
        self._filters = filters

    def to_dict(self):
        return {
            "filters": [f.to_dict() for f in self._filters]
        }

    def is_ignored(self, path: str) -> Optional[bool]:
        """Check whether a path is ignored.

        Args:
          path: Path to check
        Returns:
          True if the path matches an ignore pattern,
          False if the path is explicitly not ignored,
          or None if the file does not match any patterns.
        """
        if hasattr(path, '__fspath__'):
            path = path.__fspath__()
        status = None
        for filter in self._filters:
            status = filter.is_ignored(path)
            if status is not None:
                return status
        return status


class IgnoreFilterManager(object):
    """Ignore file manager."""

    def __init__(
            self, path: str,
            global_filters: List[IgnoreFilter],
            ignore_file_name = None,
            ignore_case: bool = False):
        if hasattr(path, '__fspath__'):
            path = path.__fspath__()
        self._path_filters = {}  # type: Dict[str, Optional[IgnoreFilter]]
        self._top_path = path
        self._global_filters = global_filters
        self._ignore_file_name = ignore_file_name
        self._ignore_case = ignore_case

    def __repr__(self) -> str:
        return "%s(%s, %r, %r)" % (
            type(self).__name__, self._top_path,
            self._global_filters,
            self._ignore_case)

    def to_dict(self, include_path_filters=True):
        d = {
            "path": self._top_path,
            "global_filters": [f.to_dict() for f in self._global_filters],
            "ignore_case": self._ignore_case,
        }
        if include_path_filters:
            d["path_filters"] = {path: f.to_dict() for path, f in self._path_filters.items() if f is not None}
        return d

    @property
    def path(self):
        return self._top_path

    @property
    def ignore_file_name(self):
        return self._ignore_file_name

    @property
    def ignore_case(self):
        return self._ignore_case

    def _load_path(self, path: str) -> Optional[IgnoreFilter]:
        try:
            return self._path_filters[path]
        except KeyError:
            pass

        if not self._ignore_file_name:
            self._path_filters[path] = None
        else:
            p = os.path.join(self._top_path, path, self._ignore_file_name)
            try:
                self._path_filters[path] = IgnoreFilter.from_path(
                    p, self._ignore_case)
            except IOError:
                self._path_filters[path] = None
        return self._path_filters[path]

    def _find_matching(self, path: str) -> Iterable[Pattern]:
        """Find matching patterns for path.

        Stops after the first ignore file with matches.

        Args:
          path: Path to check, must be relative.
        Returns:
          Iterator over Pattern instances
        """
        if hasattr(path, '__fspath__'):
            path = path.__fspath__()
        if os.path.isabs(path):
            raise ValueError('%s is an absolute path' % path)
        filters = [(0, f) for f in self._global_filters]
        if os.path.sep != '/':
            path = path.replace(os.path.sep, '/')
        parts = path.split('/')
        for i in range(len(parts)+1):
            dirname = '/'.join(parts[:i])
            for s, f in filters:
                relpath = '/'.join(parts[s:i])
                if i < len(parts):
                    # Paths leading up to the final part are all directories,
                    # so need a trailing slash.
                    relpath += '/'
                matches = list(f.find_matching(relpath))
                if matches:
                    return iter(matches)
            ignore_filter = self._load_path(dirname)
            if ignore_filter is not None:
                filters.insert(0, (i, ignore_filter))
        return iter([])

    def is_ignored(self, path: str) -> Optional[bool]:
        """Check whether a path is ignored.

        Args:
          path: Path to check, relative to the IgnoreFilterManager path
        Returns:
          True if the path matches an ignore pattern,
          False if the path is explicitly not ignored,
          or None if the file does not match any patterns.
        """
        if hasattr(path, '__fspath__'):
            path = path.__fspath__()
        matches = list(self._find_matching(path))
        if matches:
            return matches[-1].is_exclude
        return None

    def walk(self, **kwargs):
        """A wrapper for os.walk() without ignored files and subdirectories.
        kwargs are passed to walk()."""

        for dirpath, dirnames, filenames in os.walk(self.path, **kwargs):
            if dirpath == self.path:
                rel_dirpath = ''
            else:
                rel_dirpath = os.path.relpath(dirpath, self.path)

            # remove ignored subdirectories
            indices_to_remove = []
            for i, dirname in enumerate(dirnames):
                if self.is_ignored(os.path.join(rel_dirpath, dirname, '')):
                    indices_to_remove.append(i)
            for i in sorted(indices_to_remove, reverse=True):
                del dirnames[i]

            # remove ignored files
            filenames = [
                os.path.basename(f) for f in filenames if not self.is_ignored(os.path.join(rel_dirpath, f))
            ]

            # removed this as os.walk visits empty directories
            # if nothing is left, don't visit
            # if not dirnames and not filenames:
            #     continue

            yield dirpath, dirnames, filenames

    @classmethod
    def build(cls, path: str,
              global_ignore_file_paths: Iterable[str] = [],
              global_patterns: Iterable[Union[str, bytes]] = [],
              ignore_file_name: str = None,
              ignore_case: bool = False) -> 'IgnoreFilterManager':
        """Create a IgnoreFilterManager from patterns and paths.
        Args:
          path: The root path for ignore checks.
          global_ignore_file_paths: A list of file paths to load patterns from.
              Relative paths are relative to the IgnoreFilterManager path, not
              the current directory.
          global_patterns: Global patterns to ignore.
          ignore_file_name: The per-directory ignore file name.
          ignore_case: Whether to ignore case in matching.
        Returns:
          A `IgnoreFilterManager` object
        """
        if hasattr(path, '__fspath__'):
            path = path.__fspath__()
        global_filters = []
        for p in global_ignore_file_paths:
            if hasattr(p, '__fspath__'):
                p = p.__fspath__()
            p = os.path.expanduser(p)
            if not os.path.isabs(p):
                p = os.path.join(path, p)
            try:
                global_filters.append(IgnoreFilter.from_path(p))
            except IOError:
                pass
        if global_patterns:
            global_filters.append(IgnoreFilter(global_patterns))
        return cls(path,
                   global_filters=global_filters,
                   ignore_file_name=ignore_file_name,
                   ignore_case=ignore_case)
