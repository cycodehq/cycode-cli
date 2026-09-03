"""Shared reporting logic for binary scans.

The printers differ in how they draw; what they say about a binary scan should not differ at all. Everything a
printer needs to know -- which findings came from an inferred coordinate, which archives could not be identified,
whether results are partial -- is computed here once and rendered three ways.
"""

import re
from typing import TYPE_CHECKING, NamedTuple, Optional

import typer
from rich.markup import escape

from cycode.cli.files_collector.binary.base_extractor import CONFIDENCE_AMBIGUOUS
from cycode.cli.files_collector.binary.resolver import NullDigestResolver

if TYPE_CHECKING:
    from cycode.cli.files_collector.binary.collector import BinaryCollectionResult
    from cycode.cli.models import Detection, LocalScanResult

BINARY_RESULT_CONTEXT_KEY = 'binary_result'

_PACKAGE_NAME_KEY = 'package_name'
_PACKAGE_VERSION_KEY = 'package_version'

# C0 and C1 control characters, including ESC and the newlines rich does not strip
_CONTROL_CHARACTERS = re.compile(r'[\x00-\x1f\x7f-\x9f]')

_MAX_DISPLAYED_LENGTH = 180


def for_display(value: str) -> str:
    """Make a string taken from inside an untrusted archive safe to put in front of a human.

    Entry names, manifest attributes and Maven coordinates are all authored by whoever built the artifact, and an
    artifact we are asked to assess is by definition not trusted. Three things have to be neutralised before any
    of it reaches a console:

    * rich markup, or an entry named ``[link=javascript:...]x[/link].jar`` becomes a live link in a terminal and a
      raw ``href`` in an exported HTML report;
    * ANSI escapes and newlines, which rich does not strip, and which would let an artifact clear the screen or
      forge extra output lines -- including a fake coverage summary claiming full identification;
    * unbounded length, which would let one entry name push the real findings off the screen.

    The BOM keeps the true, unmodified name. This is presentation only.
    """
    cleaned = _CONTROL_CHARACTERS.sub('', value)
    if len(cleaned) > _MAX_DISPLAYED_LENGTH:
        cleaned = f'{cleaned[:_MAX_DISPLAYED_LENGTH]}...'

    return escape(cleaned)


class ComponentEvidence(NamedTuple):
    """How a component we reported a finding against was identified."""

    logical_path: str
    evidence: str
    confidence: str
    declared_scope: Optional[str] = None
    declared_via: Optional[str] = None

    @property
    def is_ambiguous(self) -> bool:
        return self.confidence == CONFIDENCE_AMBIGUOUS

    @property
    def is_declared(self) -> bool:
        """The component is not in the artifact; an embedded pom says a consumer's build would pull it in."""
        return self.declared_scope is not None

    @property
    def presence_summary(self) -> str:
        """One phrase for the printers: how a declared component got into the inventory."""
        if self.declared_via:
            return f'transitive ({self.declared_scope} scope) via {self.declared_via}, not shipped'

        return f'declared ({self.declared_scope} scope), not shipped'


class UnidentifiedEntry(NamedTuple):
    logical_path: str
    sha1: str
    size: int


class UnresolvedDeclarationEntry(NamedTuple):
    coordinate: str  # group:artifact
    version_expression: str  # what the pom wrote, or '-' when it wrote nothing
    declared_by: str
    reason: str


def get_binary_collection(ctx: typer.Context) -> Optional['BinaryCollectionResult']:
    """The collection result, or None when this was not a binary scan."""
    if not ctx.obj:
        return None

    return ctx.obj.get(BINARY_RESULT_CONTEXT_KEY)


def _component_key(group: str, artifact: str, version: str) -> tuple[str, str]:
    # the platform reports maven packages as 'group:artifact'
    name = f'{group}:{artifact}' if group else artifact
    return name, version


def build_component_index(collection: 'BinaryCollectionResult') -> dict[tuple[str, str], ComponentEvidence]:
    index: dict[tuple[str, str], ComponentEvidence] = {}

    for result in collection.results_by_artifact.values():
        for component in result.components:
            key = _component_key(component.group, component.artifact, component.version)
            index.setdefault(
                key,
                ComponentEvidence(
                    logical_path=component.logical_path,
                    evidence=component.evidence,
                    confidence=component.confidence,
                    declared_scope=component.declared_scope,
                    declared_via=component.declared_via,
                ),
            )

    return index


def get_detection_evidence(ctx: typer.Context, detection: 'Detection') -> Optional[ComponentEvidence]:
    """Where inside the artifact this finding's component lives, and how confidently we named it.

    Without this a Log4Shell hit on a 40 MB EAR gives a developer nowhere to start.
    """
    collection = get_binary_collection(ctx)
    if not collection:
        return None

    details = detection.detection_details or {}
    key = (details.get(_PACKAGE_NAME_KEY), details.get(_PACKAGE_VERSION_KEY))

    return build_component_index(collection).get(key)


def is_low_confidence(ctx: typer.Context, detection: 'Detection') -> bool:
    """True for a finding whose component was only ever identified by a manifest attribute."""
    evidence = get_detection_evidence(ctx, detection)
    return bool(evidence and evidence.is_ambiguous)


def has_gating_detections(ctx: typer.Context, local_scan_results: list['LocalScanResult']) -> bool:
    """Whether any finding is confident enough to fail a build.

    A wrong CVE from a guessed coordinate breaking someone's release costs more trust than the extra recall is
    worth, so tier 3 findings print but never gate. They are still reported, still exported, still counted.
    """
    for local_scan_result in local_scan_results:
        for document_detections in local_scan_result.document_detections:
            for detection in document_detections.detections:
                if not is_low_confidence(ctx, detection):
                    return True

    return False


def count_low_confidence(ctx: typer.Context, local_scan_results: list['LocalScanResult']) -> int:
    return sum(
        1
        for local_scan_result in local_scan_results
        for document_detections in local_scan_result.document_detections
        for detection in document_detections.detections
        if is_low_confidence(ctx, detection)
    )


def get_unidentified(collection: 'BinaryCollectionResult') -> list[UnidentifiedEntry]:
    """Every archive we could not name, in a stable order."""
    entries = [
        UnidentifiedEntry(logical_path=item.logical_path, sha1=item.sha1, size=item.size)
        for result in collection.results_by_artifact.values()
        for item in result.unidentified
    ]

    return sorted(entries, key=lambda entry: entry.logical_path)


def get_declared_unresolved(collection: 'BinaryCollectionResult') -> list[UnresolvedDeclarationEntry]:
    """Every declared dependency whose version could not be established, in a stable order."""
    entries = [
        UnresolvedDeclarationEntry(
            coordinate=item.coordinate_key,
            version_expression=item.version_expression or '-',
            declared_by=item.declared_by,
            reason=item.reason,
        )
        for item in collection.declared_unresolved
    ]

    return sorted(entries, key=lambda entry: (entry.declared_by, entry.coordinate))


def should_warn_about_degradation(ctx: typer.Context, collection: 'BinaryCollectionResult') -> bool:
    """Warn only when resolution was unavailable AND it would have made a difference.

    ``--offline`` is the user acknowledging the trade-off, so it silences the warning rather than suppressing the
    coverage numbers: the counts stay true either way.
    """
    if ctx.obj and ctx.obj.get('offline'):
        return False

    return not collection.resolver_available and collection.unidentified_count > 0


def get_coverage_summary(collection: 'BinaryCollectionResult', vulnerabilities: int) -> str:
    """One line, always present, always true.

    A manifest-only match counts as identified, but "9 identified" with three of them guessed from a manifest is a
    different result from nine exact matches, so the guessed ones are called out inline rather than folded in.
    """
    identified = f'{collection.identified_count} identified'
    if collection.low_confidence_count:
        identified += f' ({collection.low_confidence_count} low confidence)'

    parts = [identified, f'{collection.unidentified_count} unidentified']

    # only when asked for: a reader who did not pass --include-declared should not see a count that is always 0
    if collection.include_declared:
        declared = f'{collection.declared_count} declared'
        details = []
        if collection.transitive_count:
            details.append(f'{collection.transitive_count} transitive')
        unresolved = len(collection.declared_unresolved)
        if unresolved:
            details.append(f'{unresolved} unresolved')
        if details:
            declared += f' ({", ".join(details)})'
        parts.append(declared)

    parts.append(f'{vulnerabilities} vulnerabilities')
    return ' | '.join(parts)


def get_degradation_lines(collection: 'BinaryCollectionResult') -> list[str]:
    """The partial-coverage warning.

    It leads with the coverage gap rather than with the missing capability, because the gap is what the reader has
    to act on. It also says "not available in this release" rather than "unavailable": digest lookup is not a
    service that went down, it is a tier that has not shipped yet, and wording it as an outage would train people
    to wait for it to clear.
    """
    total = collection.identified_count + collection.unidentified_count
    reason = collection.resolver_unavailability_reason or NullDigestResolver().unavailability_reason
    return [
        f'{collection.unidentified_count} of {total} components could not be identified '
        f'from embedded metadata - results are PARTIAL.',
        reason,
        'Run with --offline to acknowledge and silence this warning.',
    ]


def format_size(size_in_bytes: int) -> str:
    if size_in_bytes < 1024:
        return f'{size_in_bytes} B'

    if size_in_bytes < 1024 * 1024:
        return f'{size_in_bytes / 1024:.0f} KB'

    return f'{size_in_bytes / (1024 * 1024):.1f} MB'


def count_detections(local_scan_results: list['LocalScanResult']) -> int:
    return sum(
        1
        for local_scan_result in local_scan_results
        for document_detections in local_scan_result.document_detections
        for detection in document_detections.detections
    )
