"""A structural validator for CycloneDX 1.4 documents.

Deviation from the plan, recorded deliberately: BCA-P2-08 called for validating generated output against the
vendored CycloneDX 1.4 JSON schema. That needs ``jsonschema``, which is not installed and which decision 11 forbids
adding, and it needs the schema file itself, which CI has no egress to fetch. What is asserted here instead is the
part of the specification this feature can actually violate: required fields, enumerated values, digest shapes,
bom-ref uniqueness and referential integrity of the dependency graph.

If the reviewers want true schema validation, the schema can be committed under ``tests/test_files/`` and
``jsonschema`` added as a dev dependency in a follow-up. That is a deliberate deferral, not an oversight.
"""

import re

# CycloneDX 1.4 component type enumeration
_COMPONENT_TYPES = frozenset(
    {'application', 'framework', 'library', 'container', 'operating-system', 'device', 'firmware', 'file'}
)

# the subset of the hash algorithm enumeration this feature emits
_HASH_ALGORITHMS = frozenset({'MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'})

_HASH_LENGTHS = {'MD5': 32, 'SHA-1': 40, 'SHA-256': 64, 'SHA-384': 96, 'SHA-512': 128}

_HEX = re.compile(r'^[a-fA-F0-9]+$')
_PURL = re.compile(r'^pkg:[a-zA-Z][a-zA-Z0-9.+-]*/.+$')
_TIMESTAMP = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')


def _assert_properties(properties: list) -> None:
    for entry in properties:
        assert isinstance(entry.get('name'), str), f'property needs a name: {entry}'
        assert entry['name'], f'property name must not be empty: {entry}'
        assert isinstance(entry.get('value'), str), f'property needs a string value: {entry}'


def _assert_hashes(hashes: list) -> None:
    for entry in hashes:
        algorithm = entry.get('alg')
        content = entry.get('content')

        assert algorithm in _HASH_ALGORITHMS, f'unknown hash algorithm: {algorithm}'
        assert isinstance(content, str), f'hash content must be a string: {content}'
        assert _HEX.match(content), f'hash content is not hex: {content}'
        assert len(content) == _HASH_LENGTHS[algorithm], f'{algorithm} digest has the wrong length: {content}'


def _assert_component(component: dict) -> None:
    assert component.get('type') in _COMPONENT_TYPES, f'unknown component type: {component.get("type")}'
    assert isinstance(component.get('name'), str), 'a component needs a name'
    assert component['name'], 'a component name must not be empty'

    if 'purl' in component:
        assert _PURL.match(component['purl']), f'malformed purl: {component["purl"]}'

    _assert_hashes(component.get('hashes', []))
    _assert_properties(component.get('properties', []))


def assert_valid_cyclonedx(bom: dict) -> None:
    """Assert the document is a well-formed CycloneDX 1.4 BOM with an internally consistent dependency graph."""
    assert bom.get('bomFormat') == 'CycloneDX'
    assert bom.get('specVersion') == '1.4'
    assert isinstance(bom.get('version'), int), 'BOM version must be an integer'
    assert bom['version'] >= 1, 'BOM version starts at 1'

    metadata = bom.get('metadata', {})
    assert _TIMESTAMP.match(metadata['timestamp']), f'malformed timestamp: {metadata.get("timestamp")}'
    assert metadata['tools'], 'a generated BOM should say what generated it'
    _assert_properties(metadata.get('properties', []))

    root_component = metadata['component']
    _assert_component(root_component)

    declared_refs = {root_component['bom-ref']}
    for component in bom.get('components', []):
        _assert_component(component)

        ref = component['bom-ref']
        assert ref not in declared_refs, f'duplicate bom-ref: {ref}'
        declared_refs.add(ref)

    seen_refs = set()
    for dependency in bom.get('dependencies', []):
        ref = dependency['ref']
        assert ref in declared_refs, f'dependency references an undeclared component: {ref}'
        assert ref not in seen_refs, f'duplicate dependency entry: {ref}'
        seen_refs.add(ref)

        for target in dependency.get('dependsOn', []):
            assert target in declared_refs, f'dependsOn references an undeclared component: {target}'
            assert target != ref, f'component depends on itself: {ref}'
