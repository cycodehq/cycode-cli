"""Tier 3: attributes from ``META-INF/MANIFEST.MF``.

A manifest reliably yields a name and a version but rarely a groupId, so every match from here is ambiguous and is
marked as such. We read what the jar declares about itself and stop there; deriving a groupId from a package prefix
would be a guess, and a fabricated coordinate produces a fabricated CVE list.

What the jar declares is also checked for shape before it becomes a coordinate. Real manifests carry a product name
in ``Implementation-Title`` ("Sun Java System Application Server"), a build banner in ``Implementation-Version``
("20100905 1938 [3.0.6 (2010-08-24)]") and no vendor id at all, and each of those would otherwise be reported as an
identified component. A purl assembled from them matches nothing in any index, so it is not a low-confidence
answer, it is a wrong one dressed as an answer. Those manifests yield nothing, and the jar is reported unidentified.

The format wraps lines at 72 bytes and continues them with a leading single space. The wrap is applied to *bytes*,
so a multi-byte character can be split across the boundary: continuation is therefore joined before decoding, which
is the step naive parsers get wrong.
"""

import re
from dataclasses import dataclass
from typing import Optional

from cycode.cli.files_collector.binary.identifiers.pom_properties import MavenCoordinates

_CONTINUATION_PREFIX = b' '
_ATTRIBUTE_SEPARATOR = b': '

IMPLEMENTATION_TITLE = 'Implementation-Title'
IMPLEMENTATION_VERSION = 'Implementation-Version'
IMPLEMENTATION_VENDOR_ID = 'Implementation-Vendor-Id'
BUNDLE_SYMBOLIC_NAME = 'Bundle-SymbolicName'
BUNDLE_VERSION = 'Bundle-Version'
AUTOMATIC_MODULE_NAME = 'Automatic-Module-Name'

# the characters Maven accepts in a groupId or artifactId; a product name with spaces or "::" is not a coordinate
_COORDINATE_PATTERN = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9._-]*$')
# a version starts with a digit and carries no whitespace: 2.14.1, 1.0M10, 9.4.44.v20210927, 3.0.0-SNAPSHOT
_VERSION_PATTERN = re.compile(r'^[0-9][A-Za-z0-9._+-]*$')


@dataclass(frozen=True)
class ManifestIdentity:
    coordinates: MavenCoordinates
    source_attribute: str


def parse_manifest(payload: bytes) -> dict[str, str]:
    """Return the attributes of the manifest's main section.

    Per-entry sections follow the first blank line and describe individual files rather than the artifact, so they
    are not read.
    """
    joined_lines: list[bytes] = []
    for raw_line in payload.split(b'\n'):
        line = raw_line[:-1] if raw_line.endswith(b'\r') else raw_line

        if not line.strip():
            break  # end of the main section

        if line.startswith(_CONTINUATION_PREFIX) and joined_lines:
            joined_lines[-1] += line[1:]
        else:
            joined_lines.append(line)

    attributes = {}
    for line in joined_lines:
        name, separator, value = line.partition(_ATTRIBUTE_SEPARATOR)
        if not separator:
            continue

        try:
            attributes[name.decode('utf-8').strip()] = value.decode('utf-8').strip()
        except UnicodeDecodeError:
            continue

    return attributes


def _without_directives(symbolic_name: str) -> str:
    """``com.acme.thing;singleton:=true`` is the bundle ``com.acme.thing``."""
    return symbolic_name.split(';')[0].strip()


def is_coordinate_shaped(value: Optional[str]) -> bool:
    return bool(value) and _COORDINATE_PATTERN.match(value) is not None


def is_version_shaped(value: Optional[str]) -> bool:
    return bool(value) and _VERSION_PATTERN.match(value) is not None


def identify(payload: bytes) -> Optional[ManifestIdentity]:
    """Best available coordinates, or None when the manifest says nothing usable.

    ``Implementation-Vendor-Id`` is the only source of a group because it is a declared group id, not an inference.
    Without it there is no coordinate: a purl with no namespace cannot be matched to anything, so emitting one would
    only inflate the identified count. The first attribute pair that is shaped like a coordinate wins; a pair that is
    not falls through to the next rather than disqualifying the manifest.
    """
    attributes = parse_manifest(payload)
    group = attributes.get(IMPLEMENTATION_VENDOR_ID, '').strip()
    if not is_coordinate_shaped(group):
        return None

    candidates = (
        (IMPLEMENTATION_TITLE, attributes.get(IMPLEMENTATION_TITLE), attributes.get(IMPLEMENTATION_VERSION)),
        (
            BUNDLE_SYMBOLIC_NAME,
            _without_directives(attributes.get(BUNDLE_SYMBOLIC_NAME, '')),
            attributes.get(BUNDLE_VERSION) or attributes.get(IMPLEMENTATION_VERSION),
        ),
        (
            AUTOMATIC_MODULE_NAME,
            attributes.get(AUTOMATIC_MODULE_NAME),
            attributes.get(IMPLEMENTATION_VERSION) or attributes.get(BUNDLE_VERSION),
        ),
    )

    for source_attribute, artifact, version in candidates:
        artifact = (artifact or '').strip()
        version = (version or '').strip()
        if is_coordinate_shaped(artifact) and is_version_shaped(version):
            return ManifestIdentity(
                coordinates=MavenCoordinates(group=group, artifact=artifact, version=version),
                source_attribute=source_attribute,
            )

    return None
