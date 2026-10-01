"""Matching a member against the manifest's workspaces globs.

Only reached for lockfiles that cannot name their own members: classic yarn.lock and the
binary bun.lockb. Every other format answers from the lockfile itself.
"""

import re
from pathlib import Path
from typing import NamedTuple

from cycode.cli.files_collector.sca.npm.workspace.files import FileStamp, file_stamp, read_json_object
from cycode.cli.files_collector.sca.npm.workspace.names import MANIFEST_FILE_NAME

_MANIFEST_WORKSPACES_SECTION = 'workspaces'
_MANIFEST_WORKSPACE_PACKAGES_SECTION = 'packages'
_NEGATION_PREFIX = '!'
_GLOBSTAR_SUFFIX = '/**'
_GLOBSTAR_PREFIX = '**/'


class _WorkspacePatterns(NamedTuple):
    included: tuple[str, ...]
    excluded: tuple[str, ...]


_EMPTY_WORKSPACE_PATTERNS = _WorkspacePatterns((), ())

_workspace_patterns_cache: dict[FileStamp, _WorkspacePatterns] = {}
_workspace_pattern_regex_cache: dict[str, 're.Pattern[str]'] = {}


def clear_cache() -> None:
    _workspace_patterns_cache.clear()
    _workspace_pattern_regex_cache.clear()


def _workspace_pattern_body(pattern: str) -> str:
    parts = []
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == '*' and pattern[index + 1 : index + 2] == '*':
            parts.append('.*')
            index += 2
        elif character == '*':
            parts.append('[^/]*')
            index += 1
        elif character == '?':
            parts.append('[^/]')
            index += 1
        else:
            parts.append(re.escape(character))
            index += 1

    return ''.join(parts)


def _compile_workspace_pattern(pattern: str) -> 're.Pattern[str]':
    """Translate a workspace glob, where ** spans zero or more path segments.

    Workspace members are discovered by globbing <pattern>/package.json, so src/app/**
    matches src/app itself as well as anything beneath it. pnpm records exactly that in its
    lockfile importers, and treating the trailing separator as mandatory would miss the member.
    """
    compiled = _workspace_pattern_regex_cache.get(pattern)
    if compiled is not None:
        return compiled

    body = pattern
    matches_anything_below = body.endswith(_GLOBSTAR_SUFFIX)
    if matches_anything_below:
        body = body[: -len(_GLOBSTAR_SUFFIX)]

    matches_anything_above = body.startswith(_GLOBSTAR_PREFIX)
    if matches_anything_above:
        body = body[len(_GLOBSTAR_PREFIX) :]

    expression = ''
    if matches_anything_above:
        expression += '(?:.*/)?'
    expression += _workspace_pattern_body(body)
    if matches_anything_below:
        expression += '(?:/.*)?'

    compiled = re.compile(expression)
    _workspace_pattern_regex_cache[pattern] = compiled
    return compiled


def _split_workspace_patterns(declared: list) -> _WorkspacePatterns:
    included = []
    excluded = []
    for entry in declared:
        stripped = entry.strip()
        is_excluded = stripped.startswith(_NEGATION_PREFIX)
        normalized = (stripped[1:] if is_excluded else stripped).strip()
        if normalized.startswith('./'):
            normalized = normalized[2:]

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
    if not any(_compile_workspace_pattern(pattern).fullmatch(member_path) for pattern in patterns.included):
        return False

    return not any(_compile_workspace_pattern(pattern).fullmatch(member_path) for pattern in patterns.excluded)
