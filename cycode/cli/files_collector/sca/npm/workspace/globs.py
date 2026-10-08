"""Matching a member against the manifest's workspaces globs.

Only reached for lockfiles that cannot name their own members: classic yarn.lock and the
binary bun.lockb. Every other format answers from the lockfile itself.
"""

import fnmatch
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

from cycode.cli.files_collector.sca.npm.workspace.files import FileStamp, file_stamp, read_json_object
from cycode.cli.files_collector.sca.npm.workspace.names import MANIFEST_FILE_NAME

_MANIFEST_WORKSPACES_SECTION = 'workspaces'
_MANIFEST_WORKSPACE_PACKAGES_SECTION = 'packages'
_NEGATION_PREFIX = '!'
_GLOBSTAR = '**'
_SEGMENT_MATCH_CACHE_SIZE = 4096


class _WorkspacePatterns(NamedTuple):
    included: tuple[str, ...]
    excluded: tuple[str, ...]


_EMPTY_WORKSPACE_PATTERNS = _WorkspacePatterns((), ())

_workspace_patterns_cache: dict[FileStamp, _WorkspacePatterns] = {}


def clear_cache() -> None:
    _workspace_patterns_cache.clear()


def _matches_workspace_pattern(pattern: str, member_path: str) -> bool:
    """Match a workspace glob against a member path, one path segment at a time.

    fnmatch is wrong for a whole path because its * crosses a separator, but inside one
    segment there is no separator, so it is exactly right there - and it brings character
    classes with it. Only ** needs handling here, because only ** spans segments.
    """
    return _match_segments(tuple(pattern.split('/')), tuple(member_path.split('/')))


@lru_cache(maxsize=_SEGMENT_MATCH_CACHE_SIZE)
def _match_segments(pattern_segments: tuple, path_segments: tuple) -> bool:
    """Memoised so that several ** in one pattern cannot make this exponential.

    Each ** tries every split of the remaining path, so without memoisation a pattern such as
    **/**/**/x against a deep tree multiplies out. The arguments are plain tuples of strings,
    so a result can never go stale.
    """
    if not pattern_segments:
        return not path_segments

    head, rest = pattern_segments[0], pattern_segments[1:]
    if head == _GLOBSTAR:
        # ** spans zero or more segments, and spanning zero is what makes dir/** match dir
        return any(_match_segments(rest, path_segments[index:]) for index in range(len(path_segments) + 1))

    if not path_segments:
        return False

    return fnmatch.fnmatchcase(path_segments[0], head) and _match_segments(rest, path_segments[1:])


def _split_workspace_patterns(declared: list) -> _WorkspacePatterns:
    included = []
    excluded = []
    for entry in declared:
        stripped = entry.strip()
        is_excluded = stripped.startswith(_NEGATION_PREFIX)
        normalized = (stripped[1:] if is_excluded else stripped).strip()
        normalized = normalized.removeprefix('./')

        normalized = normalized.rstrip('/')
        if not normalized:
            continue

        if is_excluded:
            excluded.append(normalized)
        else:
            included.append(normalized)

    return _WorkspacePatterns(tuple(included), tuple(excluded))


def _read_manifest_workspace_patterns(root_dir: Path) -> _WorkspacePatterns:
    manifest = root_dir / MANIFEST_FILE_NAME
    stamp = file_stamp(manifest)
    if stamp is None:
        return _EMPTY_WORKSPACE_PATTERNS

    cached = _workspace_patterns_cache.get(stamp)
    if cached is not None:
        return cached

    content = read_json_object(manifest)
    workspaces = content.get(_MANIFEST_WORKSPACES_SECTION) if content is not None else None
    if isinstance(workspaces, dict):
        workspaces = workspaces.get(_MANIFEST_WORKSPACE_PACKAGES_SECTION)

    declared = [entry for entry in workspaces if isinstance(entry, str)] if isinstance(workspaces, list) else []
    patterns = _split_workspace_patterns(declared)
    _workspace_patterns_cache[stamp] = patterns
    return patterns


def declares_workspace_member(root_dir: Path, member_path: str) -> bool:
    patterns = _read_manifest_workspace_patterns(root_dir)
    if not any(_matches_workspace_pattern(pattern, member_path) for pattern in patterns.included):
        return False

    return not any(_matches_workspace_pattern(pattern, member_path) for pattern in patterns.excluded)
