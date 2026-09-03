"""Embedded ``META-INF/maven/<groupId>/<artifactId>/pom.xml``: real dependency edges, and declared dependencies.

Containment tells us a jar sits inside a war. A pom tells us which component actually depends on which, and that is
a materially better graph. It also tells us what the component *declares* it needs, whether or not that was
packaged alongside it, which is what ``--include-declared`` reads. These are untrusted XML documents lifted out of
a customer artifact, so parsing them is the one place in this feature where a parser feature becomes an attack.

``xml.etree`` expands internal entities, which makes a billion-laughs document a live denial of service on the
Python versions this project supports, and ``defusedxml`` is not a dependency we may add. A document type
declaration is therefore refused outright before the parser ever sees the bytes. A Maven pom never legitimately
carries one, so this costs nothing and closes entity expansion, quadratic blowup and external entity resolution
together.
"""

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# matches a document type or entity declaration however it is spaced or cased
_DECLARATION_PATTERN = re.compile(r'<!\s*(DOCTYPE|ENTITY)', re.IGNORECASE)

# scopes whose dependencies are not present in the built artifact, so they are not part of what shipped
_NON_SHIPPED_SCOPES = frozenset({'test', 'provided', 'system'})

SCOPE_COMPILE = 'compile'
SCOPE_RUNTIME = 'runtime'
SCOPE_IMPORT = 'import'
TYPE_POM = 'pom'

_DEPENDENCIES_TAG = 'dependencies'
_DEPENDENCY_TAG = 'dependency'
_DEPENDENCY_MANAGEMENT_TAG = 'dependencyManagement'
_PARENT_TAG = 'parent'
_PROPERTIES_TAG = 'properties'


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


@dataclass(frozen=True)
class PomDependency:
    """One ``<dependency>`` element, exactly as written: nothing here has been interpolated or inherited."""

    group: str
    artifact: str
    version: Optional[str]
    scope: Optional[str]  # None when the element has no <scope>, which Maven reads as compile
    optional: bool = False
    type: str = 'jar'
    exclusions: frozenset = frozenset()  # 'group:artifact' keys; either part may be '*'

    @property
    def coordinate_key(self) -> str:
        return f'{self.group}:{self.artifact}'


@dataclass(frozen=True)
class ParentReference:
    group: str
    artifact: str
    version: str

    @property
    def coordinate(self) -> str:
        return f'{self.group}:{self.artifact}:{self.version}'


@dataclass
class PomModel:
    """A pom as Maven would read it before inheritance and interpolation.

    Coordinates may be missing where the pom inherits them from its parent, and any value may still contain a
    ``${property}`` reference. Resolving both is the job of the declared-dependency resolver, not of the parser.
    """

    group: Optional[str] = None
    artifact: Optional[str] = None
    version: Optional[str] = None
    parent: Optional[ParentReference] = None
    properties: dict[str, str] = field(default_factory=dict)
    dependency_management: list[PomDependency] = field(default_factory=list)
    dependencies: list[PomDependency] = field(default_factory=list)


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


def _parse_dependency(element: ET.Element) -> Optional[PomDependency]:
    group = _child_text(element, 'groupId')
    artifact = _child_text(element, 'artifactId')
    if not group or not artifact:
        return None

    scope = _child_text(element, 'scope')
    return PomDependency(
        group=group,
        artifact=artifact,
        version=_child_text(element, 'version'),
        scope=scope.lower() if scope else None,
        optional=(_child_text(element, 'optional') or '').lower() == 'true',
        type=(_child_text(element, 'type') or 'jar').lower(),
        exclusions=_parse_exclusions(element),
    )


def _parse_exclusions(element: ET.Element) -> frozenset:
    exclusions = set()
    for child in element:
        if _local_name(child.tag) != 'exclusions':
            continue

        for exclusion in child:
            if _local_name(exclusion.tag) != 'exclusion':
                continue

            group = _child_text(exclusion, 'groupId') or '*'
            artifact = _child_text(exclusion, 'artifactId') or '*'
            exclusions.add(f'{group}:{artifact}')

    return frozenset(exclusions)


def _parse_dependency_list(container: ET.Element) -> list[PomDependency]:
    dependencies = []
    for element in container:
        if _local_name(element.tag) != _DEPENDENCY_TAG:
            continue

        dependency = _parse_dependency(element)
        if dependency:
            dependencies.append(dependency)

    return dependencies


def _parse_parent(element: ET.Element) -> Optional[ParentReference]:
    group = _child_text(element, 'groupId')
    artifact = _child_text(element, 'artifactId')
    version = _child_text(element, 'version')
    if not group or not artifact or not version:
        return None

    return ParentReference(group=group, artifact=artifact, version=version)


def parse_model(payload: bytes) -> Optional[PomModel]:
    """Everything the declared-dependency resolver needs from one pom, or None when the document is unusable."""
    try:
        root = parse_xml(payload)
    except UnsafeXmlError as e:
        logger.debug('Skipping an embedded pom: %s', e)
        return None

    model = PomModel(
        group=_child_text(root, 'groupId'),
        artifact=_child_text(root, 'artifactId'),
        version=_child_text(root, 'version'),
    )

    for child in root:
        name = _local_name(child.tag)
        if name == _PARENT_TAG:
            model.parent = _parse_parent(child)
        elif name == _PROPERTIES_TAG:
            for entry in child:
                model.properties[_local_name(entry.tag)] = (entry.text or '').strip()
        elif name == _DEPENDENCIES_TAG:
            model.dependencies.extend(_parse_dependency_list(child))
        elif name == _DEPENDENCY_MANAGEMENT_TAG:
            for managed in child:
                if _local_name(managed.tag) == _DEPENDENCIES_TAG:
                    model.dependency_management.extend(_parse_dependency_list(managed))

    return model


def parse_dependencies(payload: bytes) -> list[MavenDependency]:
    """Direct dependencies declared by a pom, for drawing edges between shipped components.

    Only ``project/dependencies`` is read. Entries under ``dependencyManagement`` declare versions for modules that
    may never be depended on, and treating them as edges would invent relationships the build never made.
    """
    model = parse_model(payload)
    if model is None:
        return []

    return [
        MavenDependency(group=dependency.group, artifact=dependency.artifact, version=dependency.version)
        for dependency in model.dependencies
        if (dependency.scope or SCOPE_COMPILE) not in _NON_SHIPPED_SCOPES
    ]
