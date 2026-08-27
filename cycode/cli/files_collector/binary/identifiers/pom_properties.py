"""Tier 1: exact coordinates from ``META-INF/maven/<groupId>/<artifactId>/pom.properties``.

Written by the build that produced the jar, so this is authoritative rather than inferred. A shaded or uber jar
carries one of these per aggregated project, which is why callers get a list rather than a single answer.
"""

from dataclasses import dataclass
from typing import Optional

_COMMENT_PREFIXES = ('#', '!')
_KEY_VALUE_SEPARATORS = ('=', ':')

_GROUP_KEY = 'groupId'
_ARTIFACT_KEY = 'artifactId'
_VERSION_KEY = 'version'


@dataclass(frozen=True)
class MavenCoordinates:
    group: str
    artifact: str
    version: str


def parse_properties(payload: bytes) -> dict[str, str]:
    """Parse the subset of the Java properties format that Maven actually emits here.

    Maven writes a fixed four-line file, so the exotic corners of the format (escaped separators, multi-line values)
    do not arise. Anything unparseable is skipped rather than raising: a malformed properties file in one jar must
    not fail the scan of an entire deployable.
    """
    try:
        text = payload.decode('utf-8-sig')
    except UnicodeDecodeError:
        return {}

    properties = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(_COMMENT_PREFIXES):
            continue

        separator_index = min(
            (line.find(separator) for separator in _KEY_VALUE_SEPARATORS if line.find(separator) != -1),
            default=-1,
        )
        if separator_index <= 0:
            continue

        key = line[:separator_index].strip()
        value = line[separator_index + 1 :].strip()
        if key and value:
            properties[key] = value

    return properties


def identify(payload: bytes) -> Optional[MavenCoordinates]:
    """Coordinates from one pom.properties, or None when it does not carry a complete set."""
    properties = parse_properties(payload)

    group = properties.get(_GROUP_KEY)
    artifact = properties.get(_ARTIFACT_KEY)
    version = properties.get(_VERSION_KEY)
    if not group or not artifact or not version:
        return None

    return MavenCoordinates(group=group, artifact=artifact, version=version)
