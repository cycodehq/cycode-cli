"""Assembly of a CycloneDX 1.4 document from what the extractor identified.

Hand-written rather than generated: decision 11 rules out a new runtime dependency, and the subset of the
specification a binary-derived BOM needs is small and stable. The output is the one new artifact this feature
produces, and it is the only thing that leaves the machine.

Every field is deterministic and the ordering is stable, so two scans of the same artifact produce byte-identical
documents. That is what makes the golden-file tests meaningful and what lets a user diff two builds.
"""

import json
from datetime import datetime, timezone
from typing import Optional

from cycode import __version__
from cycode.cli.files_collector.binary.base_extractor import (
    ExtractionResult,
    IdentifiedComponent,
)

CYCLONEDX_BOM_FORMAT = 'CycloneDX'
CYCLONEDX_SPEC_VERSION = '1.4'

GRAPH_CONTAINMENT = 'containment'
GRAPH_CONTAINMENT_WITH_REAL_EDGES = 'containment+partial'

SOURCE_PROPERTY = 'cycode:source'
GRAPH_PROPERTY = 'cycode:graph'
COVERAGE_PROPERTY = 'cycode:coverage'
EVIDENCE_PROPERTY = 'cycode:evidence'
CONFIDENCE_PROPERTY = 'cycode:confidence'
PATH_PROPERTY = 'cycode:path'

BINARY_EXTRACTION_SOURCE = 'binary-extraction'

_TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def _now() -> str:
    return datetime.now(timezone.utc).strftime(_TIMESTAMP_FORMAT)


def _property(name: str, value: str) -> dict[str, str]:
    return {'name': name, 'value': value}


def _hashes(component: IdentifiedComponent) -> list[dict[str, str]]:
    hashes = [{'alg': 'SHA-1', 'content': component.sha1}]
    if component.sha256:
        hashes.append({'alg': 'SHA-256', 'content': component.sha256})

    return hashes


def build_component(component: IdentifiedComponent, paths: list[str]) -> dict:
    """One CycloneDX component. ``paths`` lists every place in the artifact this coordinate was found."""
    body = {
        'bom-ref': component.purl,
        'type': 'library',
        'name': component.artifact,
        'version': component.version,
        'purl': component.purl,
        'hashes': _hashes(component),
        'properties': [
            _property(EVIDENCE_PROPERTY, component.evidence),
            _property(CONFIDENCE_PROPERTY, component.confidence),
            _property(PATH_PROPERTY, ', '.join(paths)),
        ],
    }

    if component.group:
        body['group'] = component.group

    return body


def _deduplicate(components: list[IdentifiedComponent]) -> tuple[list[IdentifiedComponent], dict[str, list[str]]]:
    """Collapse repeats of one coordinate, keeping every path it was found at.

    A deployable that ships the same jar in two places is describing one component, not two, and emitting it twice
    would double-count it in the platform.
    """
    ordered: list[IdentifiedComponent] = []
    paths: dict[str, list[str]] = {}

    for component in components:
        if component.purl not in paths:
            ordered.append(component)
            paths[component.purl] = []

        if component.logical_path not in paths[component.purl]:
            paths[component.purl].append(component.logical_path)

    return ordered, paths


def build_bom(
    artifact_name: str,
    result: ExtractionResult,
    timestamp: Optional[str] = None,
) -> dict:
    """Assemble the document handed to the SCA pipeline."""
    components, paths = _deduplicate(result.components)
    root_ref = artifact_name

    identified_count = len(components)
    total_count = identified_count + len(result.unidentified)
    graph_kind = GRAPH_CONTAINMENT_WITH_REAL_EDGES if result.has_real_edges else GRAPH_CONTAINMENT

    return {
        'bomFormat': CYCLONEDX_BOM_FORMAT,
        'specVersion': CYCLONEDX_SPEC_VERSION,
        'version': 1,
        'metadata': {
            'timestamp': timestamp or _now(),
            'tools': [{'vendor': 'Cycode', 'name': 'cycode-cli', 'version': __version__}],
            'component': {'bom-ref': root_ref, 'type': 'application', 'name': artifact_name},
            'properties': [
                _property(SOURCE_PROPERTY, BINARY_EXTRACTION_SOURCE),
                _property(GRAPH_PROPERTY, graph_kind),
                _property(COVERAGE_PROPERTY, f'{identified_count}/{total_count}'),
            ],
        },
        'components': [build_component(component, paths[component.purl]) for component in components],
        'dependencies': _build_dependencies(root_ref, components, result.dependency_edges),
    }


def _build_dependencies(
    root_ref: str,
    components: list[IdentifiedComponent],
    edges: dict[str, list[str]],
) -> list[dict]:
    """Every ref gets an entry, so a leaf reads as "depends on nothing" rather than as missing data."""
    known_refs = {component.purl for component in components}

    entries = []
    for ref in [root_ref, *sorted(known_refs)]:
        depends_on = sorted(target for target in edges.get(ref, []) if target in known_refs)
        entries.append({'ref': ref, 'dependsOn': depends_on})

    return entries


def to_json(bom: dict) -> str:
    """Serialise with stable formatting. Key order is the insertion order above, which is the readable one."""
    return json.dumps(bom, indent=2, ensure_ascii=False)


def build_bom_json(artifact_name: str, result: ExtractionResult, timestamp: Optional[str] = None) -> str:
    return to_json(build_bom(artifact_name, result, timestamp))
