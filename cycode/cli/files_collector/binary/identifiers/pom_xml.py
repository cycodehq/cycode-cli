"""Real dependency edges from an embedded ``META-INF/maven/<groupId>/<artifactId>/pom.xml``.

Containment tells us a jar sits inside a war. A pom tells us which component actually depends on which, and that is
a materially better graph. These are untrusted XML documents lifted out of a customer artifact, so parsing them is
the one place in this feature where a parser feature becomes an attack.

``xml.etree`` expands internal entities, which makes a billion-laughs document a live denial of service on the
Python versions this project supports, and ``defusedxml`` is not a dependency we may add. A document type
declaration is therefore refused outright before the parser ever sees the bytes. A Maven pom never legitimately
carries one, so this costs nothing and closes entity expansion, quadratic blowup and external entity resolution
together.
"""

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# matches a document type or entity declaration however it is spaced or cased
_DECLARATION_PATTERN = re.compile(r'<!\s*(DOCTYPE|ENTITY)', re.IGNORECASE)

# scopes whose dependencies are not present in the built artifact, so they are not part of what shipped
_NON_SHIPPED_SCOPES = frozenset({'test', 'provided', 'system'})

_DEPENDENCIES_TAG = 'dependencies'
_DEPENDENCY_TAG = 'dependency'


class UnsafeXmlError(ValueError):
    """The document carries a declaration we refuse to hand to the parser."""


@dataclass(frozen=True)
class MavenDependency:
    group: str
    artifact: str
    version: Optional[str]

    @property
    def coordinate_key(self) -> str:
        """Version is frequently a property reference we cannot resolve, so edges are matched on group:artifact."""
        return f'{self.group}:{self.artifact}'


def _local_name(tag: str) -> str:
    """``{http://maven.apache.org/POM/4.0.0}dependency`` is a ``dependency``."""
    return tag.rsplit('}', 1)[-1]


def _child_text(element: ET.Element, name: str) -> Optional[str]:
    for child in element:
        if _local_name(child.tag) == name:
            return (child.text or '').strip() or None

    return None


def parse_xml(payload: bytes) -> ET.Element:
    """Parse an untrusted XML document, refusing anything with a document type declaration.

    The guard runs on *decoded text*, not on the raw bytes. Scanning bytes for ``<!DOCTYPE`` looks equivalent but
    is not: expat sniffs a UTF-16 byte-order mark and happily parses the DTD of a document whose declaration the
    byte-level pattern never matched. Decoding first collapses every encoding to one representation the guard can
    actually see, and a pom that is not UTF-8 is refused rather than guessed at -- Maven writes UTF-8.
    """
    try:
        text = payload.decode('utf-8-sig')
    except UnicodeDecodeError as e:
        raise UnsafeXmlError(f'XML document is not valid UTF-8 and was not parsed: {e}') from e

    if _DECLARATION_PATTERN.search(text):
        raise UnsafeXmlError('XML document carries a document type or entity declaration and was not parsed.')

    try:
        return ET.fromstring(text)  # noqa: S314 - declarations are refused above
    except ET.ParseError as e:
        raise UnsafeXmlError(f'XML document could not be parsed: {e}') from e


def parse_dependencies(payload: bytes) -> list[MavenDependency]:
    """Direct dependencies declared by a pom.

    Only ``project/dependencies`` is read. Entries under ``dependencyManagement`` declare versions for modules that
    may never be depended on, and treating them as edges would invent relationships the build never made.
    """
    try:
        root = parse_xml(payload)
    except UnsafeXmlError as e:
        logger.debug('Skipping an embedded pom: %s', e)
        return []

    dependencies = []
    for child in root:
        if _local_name(child.tag) != _DEPENDENCIES_TAG:
            continue

        for element in child:
            if _local_name(element.tag) != _DEPENDENCY_TAG:
                continue

            scope = (_child_text(element, 'scope') or '').lower()
            if scope in _NON_SHIPPED_SCOPES:
                continue

            group = _child_text(element, 'groupId')
            artifact = _child_text(element, 'artifactId')
            if not group or not artifact:
                continue

            dependencies.append(
                MavenDependency(group=group, artifact=artifact, version=_child_text(element, 'version'))
            )

    return dependencies
