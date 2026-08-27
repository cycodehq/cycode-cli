import copy
import json
from pathlib import Path
from typing import ClassVar

import pytest

from cycode.cli.files_collector.binary import cyclonedx_builder
from cycode.cli.files_collector.binary.base_extractor import (
    CONFIDENCE_AMBIGUOUS,
    CONFIDENCE_EXACT,
    EVIDENCE_MANIFEST,
    EVIDENCE_POM_PROPERTIES,
    ExtractionResult,
    IdentifiedComponent,
    UnidentifiedArtifact,
)
from cycode.cli.files_collector.binary.java_extractor import JavaArchiveExtractor
from tests.cli.files_collector.binary import fixtures
from tests.cli.files_collector.binary.cyclonedx_assertions import assert_valid_cyclonedx

_FIXED_TIMESTAMP = '2026-08-26T12:00:00Z'

_GUAVA = ('com.google.guava', 'guava', '31.1-jre')
_LOG4J = ('org.apache.logging.log4j', 'log4j-core', '2.14.1')
_SLF4J = ('org.slf4j', 'slf4j-api', '1.7.36')


def _component(
    group: str,
    artifact: str,
    version: str,
    logical_path: str = 'app.war > WEB-INF/lib/x.jar',
    parent: str = 'app.war',
    evidence: str = EVIDENCE_POM_PROPERTIES,
    confidence: str = CONFIDENCE_EXACT,
) -> IdentifiedComponent:
    return IdentifiedComponent(
        group=group,
        artifact=artifact,
        version=version,
        sha1='a' * 40,
        sha256='b' * 64,
        logical_path=logical_path,
        parent=parent,
        evidence=evidence,
        confidence=confidence,
    )


def _build(result: ExtractionResult, artifact_name: str = 'app.war') -> dict:
    return cyclonedx_builder.build_bom(artifact_name, result, timestamp=_FIXED_TIMESTAMP)


def _normalise(bom: dict) -> dict:
    """Blank out digests so a golden document survives zlib differences across the CI matrix.

    Compressed bytes vary with the zlib build, so the digest of a generated fixture archive is not stable across
    six Python versions and three operating systems. The digests are asserted separately, against what the
    extractor actually computed.
    """
    normalised = copy.deepcopy(bom)
    for component in normalised.get('components', []):
        for digest in component.get('hashes', []):
            digest['content'] = f'<{digest["alg"]}>'

    normalised['metadata']['tools'] = ['<tools>']
    return normalised


class TestDocumentStructure:
    def test_an_empty_result_is_still_a_valid_document(self) -> None:
        bom = _build(ExtractionResult())

        assert_valid_cyclonedx(bom)
        assert bom['components'] == []
        assert bom['metadata']['component']['name'] == 'app.war'
        assert bom['metadata']['component']['type'] == 'application'

    def test_metadata_records_provenance(self) -> None:
        result = ExtractionResult(
            components=[_component(*_GUAVA)],
            unidentified=[UnidentifiedArtifact('app.war > WEB-INF/lib/shim.jar', 'c' * 40, 44)],
        )

        properties = {entry['name']: entry['value'] for entry in _build(result)['metadata']['properties']}

        assert properties['cycode:source'] == 'binary-extraction'
        assert properties['cycode:coverage'] == '1/2'
        assert properties['cycode:graph'] == 'containment'

    def test_graph_kind_reflects_recovered_edges(self) -> None:
        result = ExtractionResult(components=[_component(*_GUAVA)], has_real_edges=True)

        properties = {entry['name']: entry['value'] for entry in _build(result)['metadata']['properties']}

        assert properties['cycode:graph'] == 'containment+partial'

    def test_output_is_deterministic(self) -> None:
        result = ExtractionResult(components=[_component(*_GUAVA), _component(*_LOG4J)])

        first = cyclonedx_builder.build_bom_json('app.war', result, timestamp=_FIXED_TIMESTAMP)
        second = cyclonedx_builder.build_bom_json('app.war', result, timestamp=_FIXED_TIMESTAMP)

        assert first == second
        assert json.loads(first)['specVersion'] == '1.4'


class TestComponents:
    def test_a_component_carries_its_coordinates_and_digests(self) -> None:
        bom = _build(ExtractionResult(components=[_component(*_GUAVA)]))
        component = bom['components'][0]

        assert component['bom-ref'] == 'pkg:maven/com.google.guava/guava@31.1-jre'
        assert component['purl'] == 'pkg:maven/com.google.guava/guava@31.1-jre'
        assert component['group'] == 'com.google.guava'
        assert component['name'] == 'guava'
        assert component['version'] == '31.1-jre'
        assert component['type'] == 'library'
        assert component['hashes'] == [
            {'alg': 'SHA-1', 'content': 'a' * 40},
            {'alg': 'SHA-256', 'content': 'b' * 64},
        ]

    def test_evidence_and_confidence_are_recorded(self) -> None:
        result = ExtractionResult(
            components=[_component('', 'widget', '1.0', evidence=EVIDENCE_MANIFEST, confidence=CONFIDENCE_AMBIGUOUS)]
        )

        properties = {entry['name']: entry['value'] for entry in _build(result)['components'][0]['properties']}

        assert properties['cycode:evidence'] == 'manifest.mf'
        assert properties['cycode:confidence'] == 'ambiguous'

    def test_a_component_with_no_group_omits_it_rather_than_inventing_one(self) -> None:
        bom = _build(ExtractionResult(components=[_component('', 'widget', '1.0')]))
        component = bom['components'][0]

        assert 'group' not in component
        assert component['purl'] == 'pkg:maven/widget@1.0'
        assert_valid_cyclonedx(bom)

    def test_the_same_coordinate_shipped_twice_is_one_component_with_both_paths(self) -> None:
        result = ExtractionResult(
            components=[
                _component(*_GUAVA, logical_path='app.war > WEB-INF/lib/guava.jar'),
                _component(*_GUAVA, logical_path='app.war > WEB-INF/lib/guava-shadow.jar'),
            ]
        )

        bom = _build(result)

        assert len(bom['components']) == 1
        paths = {entry['name']: entry['value'] for entry in bom['components'][0]['properties']}['cycode:path']
        assert paths == 'app.war > WEB-INF/lib/guava.jar, app.war > WEB-INF/lib/guava-shadow.jar'
        assert_valid_cyclonedx(bom)

    def test_no_digest_means_no_sha256_entry(self) -> None:
        component = IdentifiedComponent(
            group='com.acme',
            artifact='widget',
            version='1.0',
            sha1='a' * 40,
            logical_path='app.war > WEB-INF/lib/widget.jar',
            parent='app.war',
            evidence=EVIDENCE_POM_PROPERTIES,
            confidence=CONFIDENCE_EXACT,
        )

        bom = _build(ExtractionResult(components=[component]))

        assert bom['components'][0]['hashes'] == [{'alg': 'SHA-1', 'content': 'a' * 40}]
        assert_valid_cyclonedx(bom)


class TestDependencyGraph:
    def test_every_component_appears_even_with_no_edges(self) -> None:
        # an absent entry reads as missing data; an empty dependsOn reads as "depends on nothing"
        result = ExtractionResult(components=[_component(*_GUAVA), _component(*_LOG4J)])

        refs = [entry['ref'] for entry in _build(result)['dependencies']]

        assert refs == [
            'app.war',
            'pkg:maven/com.google.guava/guava@31.1-jre',
            'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
        ]

    def test_edges_are_emitted_and_sorted(self) -> None:
        result = ExtractionResult(
            components=[_component(*_GUAVA), _component(*_LOG4J)],
            dependency_edges={
                'app.war': [
                    'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
                    'pkg:maven/com.google.guava/guava@31.1-jre',
                ]
            },
        )

        bom = _build(result)
        root_entry = next(entry for entry in bom['dependencies'] if entry['ref'] == 'app.war')

        assert root_entry['dependsOn'] == [
            'pkg:maven/com.google.guava/guava@31.1-jre',
            'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
        ]
        assert_valid_cyclonedx(bom)

    def test_an_edge_to_an_unknown_component_is_dropped(self) -> None:
        # a pom can name a dependency that was never actually shipped inside the artifact
        result = ExtractionResult(
            components=[_component(*_GUAVA)],
            dependency_edges={'app.war': ['pkg:maven/never/shipped@1.0']},
        )

        bom = _build(result)

        assert bom['dependencies'][0]['dependsOn'] == []
        assert_valid_cyclonedx(bom)


class TestAgainstRealArtifacts:
    def _extract(self, tmp_path: Path, name: str, content: bytes) -> tuple[dict, ExtractionResult]:
        path = tmp_path / name
        path.write_bytes(content)

        extractor = JavaArchiveExtractor()
        result = extractor.identify(extractor.extract(str(path)))
        return cyclonedx_builder.build_bom(name, result, timestamp=_FIXED_TIMESTAMP), result

    def test_a_war_produces_a_valid_document(self, tmp_path: Path) -> None:
        war = fixtures.war_bytes(
            libraries={
                'guava-31.1-jre.jar': fixtures.library_jar(*_GUAVA),
                'log4j-core-2.14.1.jar': fixtures.library_jar(*_LOG4J),
            }
        )

        bom, result = self._extract(tmp_path, 'payments.war', war)

        assert_valid_cyclonedx(bom)
        assert [component['purl'] for component in bom['components']] == [
            'pkg:maven/com.google.guava/guava@31.1-jre',
            'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
        ]
        # the digests in the document are the ones the extractor actually computed
        emitted = {component['hashes'][0]['content'] for component in bom['components']}
        assert emitted == {component.sha1 for component in result.components}

    def test_an_ear_nests_containment_edges(self, tmp_path: Path) -> None:
        inner_war = fixtures.war_bytes(libraries={'log4j-core.jar': fixtures.library_jar(*_LOG4J)})
        ear = fixtures.ear_bytes(
            modules={'web.war': inner_war},
            libraries={'guava.jar': fixtures.library_jar(*_GUAVA)},
        )

        bom, _ = self._extract(tmp_path, 'payments.ear', ear)
        edges = {entry['ref']: entry['dependsOn'] for entry in bom['dependencies']}

        assert_valid_cyclonedx(bom)
        # the war is not a Maven artifact here, so the jar inside it attaches to the nearest thing we can name
        assert 'pkg:maven/com.google.guava/guava@31.1-jre' in edges['payments.ear']
        assert 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1' in edges['payments.ear']

    def test_a_real_pom_edge_replaces_the_containment_edge(self, tmp_path: Path) -> None:
        # guava declares slf4j, so slf4j hangs off guava rather than off the application
        pom = b"""<?xml version="1.0"?>
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <groupId>com.google.guava</groupId>
          <artifactId>guava</artifactId>
          <version>31.1-jre</version>
          <dependencies>
            <dependency>
              <groupId>org.slf4j</groupId>
              <artifactId>slf4j-api</artifactId>
              <version>1.7.36</version>
            </dependency>
          </dependencies>
        </project>"""

        guava = fixtures.archive_bytes(
            files={
                fixtures.pom_properties_entry_name(*_GUAVA[:2]): fixtures.pom_properties(*_GUAVA),
                f'META-INF/maven/{_GUAVA[0]}/{_GUAVA[1]}/pom.xml': pom,
            }
        )
        war = fixtures.war_bytes(libraries={'guava.jar': guava, 'slf4j-api.jar': fixtures.library_jar(*_SLF4J)})

        bom, result = self._extract(tmp_path, 'payments.war', war)
        edges = {entry['ref']: entry['dependsOn'] for entry in bom['dependencies']}

        assert_valid_cyclonedx(bom)
        assert result.has_real_edges is True
        assert edges['pkg:maven/com.google.guava/guava@31.1-jre'] == ['pkg:maven/org.slf4j/slf4j-api@1.7.36']
        # the containment edge was dropped in favour of the real one
        assert edges['payments.war'] == ['pkg:maven/com.google.guava/guava@31.1-jre']

    def test_a_shaded_jar_yields_one_component_per_aggregated_project(self, tmp_path: Path) -> None:
        shaded = fixtures.archive_bytes(
            files={
                fixtures.pom_properties_entry_name(*_GUAVA[:2]): fixtures.pom_properties(*_GUAVA),
                fixtures.pom_properties_entry_name(*_SLF4J[:2]): fixtures.pom_properties(*_SLF4J),
            }
        )

        bom, _ = self._extract(tmp_path, 'uber.jar', fixtures.war_bytes(libraries={'shaded.jar': shaded}))

        assert_valid_cyclonedx(bom)
        assert {component['purl'] for component in bom['components']} == {
            'pkg:maven/com.google.guava/guava@31.1-jre',
            'pkg:maven/org.slf4j/slf4j-api@1.7.36',
        }

    def test_a_tier_three_component_is_marked_ambiguous(self, tmp_path: Path) -> None:
        manifest_only = fixtures.archive_bytes(
            files={
                'META-INF/MANIFEST.MF': fixtures.manifest(
                    Implementation_Title='mystery-lib',
                    Implementation_Version='4.2',
                    Implementation_Vendor_Id='com.acme',
                )
            }
        )

        bom, _ = self._extract(tmp_path, 'app.war', fixtures.war_bytes(libraries={'mystery.jar': manifest_only}))
        properties = {entry['name']: entry['value'] for entry in bom['components'][0]['properties']}

        assert_valid_cyclonedx(bom)
        assert properties['cycode:confidence'] == 'ambiguous'
        assert properties['cycode:evidence'] == 'manifest.mf'
        assert bom['components'][0]['purl'] == 'pkg:maven/com.acme/mystery-lib@4.2'


class TestGoldenDocument:
    """Catches silent regressions in ordering, deduplication and edge construction."""

    _EXPECTED: ClassVar[dict] = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.4',
        'version': 1,
        'metadata': {
            'timestamp': _FIXED_TIMESTAMP,
            'tools': ['<tools>'],
            'component': {'bom-ref': 'payments.war', 'type': 'application', 'name': 'payments.war'},
            'properties': [
                {'name': 'cycode:source', 'value': 'binary-extraction'},
                {'name': 'cycode:graph', 'value': 'containment'},
                {'name': 'cycode:coverage', 'value': '2/3'},
            ],
        },
        'components': [
            {
                'bom-ref': 'pkg:maven/com.google.guava/guava@31.1-jre',
                'type': 'library',
                'name': 'guava',
                'version': '31.1-jre',
                'purl': 'pkg:maven/com.google.guava/guava@31.1-jre',
                'hashes': [{'alg': 'SHA-1', 'content': '<SHA-1>'}, {'alg': 'SHA-256', 'content': '<SHA-256>'}],
                'properties': [
                    {'name': 'cycode:evidence', 'value': 'pom.properties'},
                    {'name': 'cycode:confidence', 'value': 'exact'},
                    {'name': 'cycode:path', 'value': 'payments.war > WEB-INF/lib/guava-31.1-jre.jar'},
                ],
                'group': 'com.google.guava',
            },
            {
                'bom-ref': 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
                'type': 'library',
                'name': 'log4j-core',
                'version': '2.14.1',
                'purl': 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
                'hashes': [{'alg': 'SHA-1', 'content': '<SHA-1>'}, {'alg': 'SHA-256', 'content': '<SHA-256>'}],
                'properties': [
                    {'name': 'cycode:evidence', 'value': 'pom.properties'},
                    {'name': 'cycode:confidence', 'value': 'exact'},
                    {'name': 'cycode:path', 'value': 'payments.war > WEB-INF/lib/log4j-core-2.14.1.jar'},
                ],
                'group': 'org.apache.logging.log4j',
            },
        ],
        'dependencies': [
            {
                'ref': 'payments.war',
                'dependsOn': [
                    'pkg:maven/com.google.guava/guava@31.1-jre',
                    'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
                ],
            },
            {'ref': 'pkg:maven/com.google.guava/guava@31.1-jre', 'dependsOn': []},
            {'ref': 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', 'dependsOn': []},
        ],
    }

    @pytest.fixture
    def bom(self, tmp_path: Path) -> dict:
        war = fixtures.war_bytes(
            libraries={
                'guava-31.1-jre.jar': fixtures.library_jar(*_GUAVA),
                'log4j-core-2.14.1.jar': fixtures.library_jar(*_LOG4J),
                'internal-shim.jar': fixtures.archive_bytes(files={'com/acme/Shim.class': b'\xca\xfe\xba\xbe'}),
            }
        )
        path = tmp_path / 'payments.war'
        path.write_bytes(war)

        extractor = JavaArchiveExtractor()
        result = extractor.identify(extractor.extract(str(path)))
        return cyclonedx_builder.build_bom('payments.war', result, timestamp=_FIXED_TIMESTAMP)

    def test_matches_the_golden_document(self, bom: dict) -> None:
        assert _normalise(bom) == self._EXPECTED

    def test_the_golden_document_is_valid(self, bom: dict) -> None:
        assert_valid_cyclonedx(bom)
