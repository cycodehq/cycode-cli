from typing import Optional
from unittest.mock import MagicMock

import pytest
import typer

from cycode.cli.files_collector.binary.base_extractor import (
    CONFIDENCE_AMBIGUOUS,
    CONFIDENCE_EXACT,
    EVIDENCE_MANIFEST,
    EVIDENCE_POM_PROPERTIES,
    EVIDENCE_POM_XML,
    ExtractionResult,
    IdentifiedComponent,
    UnidentifiedArtifact,
    UnresolvedDeclaration,
)
from cycode.cli.files_collector.binary.collector import BinaryCollectionResult
from cycode.cli.models import DocumentDetections, LocalScanResult
from cycode.cli.printers.utils import binary_report
from cycode.cyclient.models import Detection

_LOG4J = ('org.apache.logging.log4j', 'log4j-core', '2.14.1')
_MYSTERY = ('', 'mystery-lib', '4.2')


def _component(
    group: str,
    artifact: str,
    version: str,
    logical_path: str = 'app.war > WEB-INF/lib/x.jar',
    evidence: str = EVIDENCE_POM_PROPERTIES,
    confidence: str = CONFIDENCE_EXACT,
) -> IdentifiedComponent:
    return IdentifiedComponent(
        group=group,
        artifact=artifact,
        version=version,
        sha1='a' * 40,
        logical_path=logical_path,
        parent='app.war',
        evidence=evidence,
        confidence=confidence,
    )


def _collection(
    components: Optional[list] = None,
    unidentified: Optional[list] = None,
    resolver_available: bool = False,
) -> BinaryCollectionResult:
    collection = BinaryCollectionResult()
    collection.results_by_artifact['app.war'] = ExtractionResult(
        components=components or [],
        unidentified=unidentified or [],
        resolver_available=resolver_available,
    )
    return collection


def _ctx(collection: Optional[BinaryCollectionResult] = None, offline: bool = False) -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'offline': offline}
    if collection is not None:
        ctx.obj['binary_result'] = collection
    return ctx


def _detection(package_name: str, package_version: str) -> Detection:
    return Detection(
        detection_type_id='id',
        type='sca',
        message='msg',
        detection_details={'package_name': package_name, 'package_version': package_version},
        detection_rule_id='rule',
        severity='Critical',
    )


def _scan_results(*detections: Detection) -> list:
    document = MagicMock()
    return [
        LocalScanResult(
            scan_id='scan',
            report_url=None,
            document_detections=[DocumentDetections(document=document, detections=list(detections))],
            issue_detected=bool(detections),
            detections_count=len(detections),
            relevant_detections_count=len(detections),
        )
    ]


class TestGetBinaryCollection:
    def test_absent_for_a_normal_scan(self) -> None:
        assert binary_report.get_binary_collection(_ctx()) is None

    def test_present_for_a_binary_scan(self) -> None:
        collection = _collection()

        assert binary_report.get_binary_collection(_ctx(collection)) is collection


class TestDetectionEvidence:
    def test_a_finding_is_matched_back_to_its_component(self) -> None:
        collection = _collection(components=[_component(*_LOG4J, logical_path='app.war > WEB-INF/lib/log4j.jar')])
        detection = _detection('org.apache.logging.log4j:log4j-core', '2.14.1')

        evidence = binary_report.get_detection_evidence(_ctx(collection), detection)

        assert evidence.logical_path == 'app.war > WEB-INF/lib/log4j.jar'
        assert evidence.evidence == EVIDENCE_POM_PROPERTIES
        assert evidence.is_ambiguous is False

    def test_a_component_with_no_group_is_matched_on_its_name_alone(self) -> None:
        collection = _collection(components=[_component(*_MYSTERY, evidence=EVIDENCE_MANIFEST)])
        detection = _detection('mystery-lib', '4.2')

        assert binary_report.get_detection_evidence(_ctx(collection), detection) is not None

    def test_a_version_mismatch_does_not_match(self) -> None:
        collection = _collection(components=[_component(*_LOG4J)])
        detection = _detection('org.apache.logging.log4j:log4j-core', '2.17.1')

        assert binary_report.get_detection_evidence(_ctx(collection), detection) is None

    def test_nothing_is_matched_on_a_normal_scan(self) -> None:
        assert binary_report.get_detection_evidence(_ctx(), _detection('a:b', '1')) is None


class TestExitCodeGating:
    def test_an_exact_finding_gates_the_build(self) -> None:
        collection = _collection(components=[_component(*_LOG4J)])
        results = _scan_results(_detection('org.apache.logging.log4j:log4j-core', '2.14.1'))

        assert binary_report.has_gating_detections(_ctx(collection), results) is True

    def test_a_tier_three_finding_does_not_gate_the_build(self) -> None:
        # a fabricated CVE from a guessed coordinate must never break someone's release
        collection = _collection(
            components=[_component(*_MYSTERY, evidence=EVIDENCE_MANIFEST, confidence=CONFIDENCE_AMBIGUOUS)]
        )
        results = _scan_results(_detection('mystery-lib', '4.2'))

        assert binary_report.has_gating_detections(_ctx(collection), results) is False
        assert binary_report.count_low_confidence(_ctx(collection), results) == 1

    def test_one_exact_finding_among_ambiguous_ones_still_gates(self) -> None:
        collection = _collection(
            components=[
                _component(*_LOG4J),
                _component(*_MYSTERY, evidence=EVIDENCE_MANIFEST, confidence=CONFIDENCE_AMBIGUOUS),
            ]
        )
        results = _scan_results(
            _detection('mystery-lib', '4.2'),
            _detection('org.apache.logging.log4j:log4j-core', '2.14.1'),
        )

        assert binary_report.has_gating_detections(_ctx(collection), results) is True

    def test_a_finding_we_cannot_match_is_treated_as_gating(self) -> None:
        # failing open here would silently drop real findings; low confidence has to be proven, not assumed
        collection = _collection(components=[_component(*_LOG4J)])
        results = _scan_results(_detection('something:unmatched', '9.9'))

        assert binary_report.has_gating_detections(_ctx(collection), results) is True


class TestDegradationWarning:
    def test_warns_when_resolution_was_unavailable_and_something_went_unidentified(self) -> None:
        collection = _collection(
            unidentified=[UnidentifiedArtifact('app.war > WEB-INF/lib/shim.jar', 'b' * 40, 44)],
            resolver_available=False,
        )

        assert binary_report.should_warn_about_degradation(_ctx(collection), collection) is True

    def test_does_not_warn_when_everything_was_identified(self) -> None:
        collection = _collection(components=[_component(*_LOG4J)], resolver_available=False)

        assert binary_report.should_warn_about_degradation(_ctx(collection), collection) is False

    def test_offline_silences_the_warning(self) -> None:
        collection = _collection(
            unidentified=[UnidentifiedArtifact('app.war > WEB-INF/lib/shim.jar', 'b' * 40, 44)],
            resolver_available=False,
        )

        assert binary_report.should_warn_about_degradation(_ctx(collection, offline=True), collection) is False

    def test_offline_does_not_change_the_counts(self) -> None:
        # acknowledging the trade-off silences the warning; it must not make the numbers less true
        collection = _collection(
            components=[_component(*_LOG4J)],
            unidentified=[UnidentifiedArtifact('app.war > WEB-INF/lib/shim.jar', 'b' * 40, 44)],
        )

        assert binary_report.get_coverage_summary(collection, 3) == '1 identified | 1 unidentified | 3 vulnerabilities'

    def test_manifest_only_matches_are_called_out_in_the_coverage_line(self) -> None:
        # "2 identified" with one of them guessed from a manifest is a different result from two exact matches
        collection = _collection(
            components=[
                _component(*_LOG4J),
                _component(*_MYSTERY, evidence=EVIDENCE_MANIFEST, confidence=CONFIDENCE_AMBIGUOUS),
            ],
            unidentified=[UnidentifiedArtifact('app.war > WEB-INF/lib/shim.jar', 'b' * 40, 44)],
        )

        assert collection.low_confidence_count == 1
        assert (
            binary_report.get_coverage_summary(collection, 0)
            == '2 identified (1 low confidence) | 1 unidentified | 0 vulnerabilities'
        )


class TestUnidentified:
    def test_entries_are_sorted_for_a_stable_diff(self) -> None:
        collection = _collection(
            unidentified=[
                UnidentifiedArtifact('app.war > WEB-INF/lib/z.jar', 'c' * 40, 10),
                UnidentifiedArtifact('app.war > WEB-INF/lib/a.jar', 'd' * 40, 20),
            ]
        )

        assert [entry.logical_path for entry in binary_report.get_unidentified(collection)] == [
            'app.war > WEB-INF/lib/a.jar',
            'app.war > WEB-INF/lib/z.jar',
        ]


class TestFormatSize:
    @pytest.mark.parametrize(
        ('size', 'expected'),
        [(0, '0 B'), (512, '512 B'), (1024, '1 KB'), (44000, '43 KB'), (5 * 1024 * 1024, '5.0 MB')],
    )
    def test_human_readable_sizes(self, size: int, expected: str) -> None:
        assert binary_report.format_size(size) == expected


class TestDegradationWording:
    """The warning must not read like a transient outage: tier 2 has not shipped, it has not gone down."""

    def _lines(self) -> list:
        collection = _collection(
            components=[_component(*_LOG4J)],
            unidentified=[UnidentifiedArtifact('app.war > WEB-INF/lib/shim.jar', 'b' * 40, 44)],
        )
        return binary_report.get_degradation_lines(collection)

    def test_it_leads_with_the_coverage_gap(self) -> None:
        assert self._lines()[0].startswith('1 of 2 components could not be identified')

    def test_it_says_partial(self) -> None:
        assert 'PARTIAL' in ' '.join(self._lines())

    def test_it_does_not_imply_an_outage(self) -> None:
        text = ' '.join(self._lines())

        # "unavailable" reads as "it broke, try later"; this tier has simply not been built yet
        assert 'not available in this release' in text
        assert 'lookup unavailable' not in text

    def test_it_names_the_way_out(self) -> None:
        text = ' '.join(self._lines())

        assert '--offline' in text
        assert '--maven-central' in text

    def test_a_lookup_that_failed_says_so_instead(self) -> None:
        collection = _collection(
            components=[_component(*_LOG4J)],
            unidentified=[UnidentifiedArtifact('app.war > WEB-INF/lib/shim.jar', 'b' * 40, 44)],
        )
        collection.results_by_artifact[
            'app.war'
        ].resolver_unavailability_reason = (
            'Maven Central lookup failed (timed out); digests after that point were not resolved.'
        )

        text = ' '.join(binary_report.get_degradation_lines(collection))

        assert 'Maven Central lookup failed (timed out)' in text
        assert 'not available in this release' not in text


def _declared(
    group: str, artifact: str, version: str, scope: str = 'compile', via: Optional[str] = None
) -> IdentifiedComponent:
    return IdentifiedComponent(
        group=group,
        artifact=artifact,
        version=version,
        sha1=None,
        logical_path='app.war > WEB-INF/lib/x.jar > META-INF/maven/g/x/pom.xml',
        parent='app.war > WEB-INF/lib/x.jar',
        evidence=EVIDENCE_POM_XML,
        confidence=CONFIDENCE_EXACT,
        declared_scope=scope,
        declared_via=via,
    )


class TestDeclared:
    def test_the_coverage_line_mentions_declared_only_when_asked(self) -> None:
        collection = _collection(components=[_component(*_LOG4J), _declared('a', 'b', '1')])

        assert binary_report.get_coverage_summary(collection, 0) == '1 identified | 0 unidentified | 0 vulnerabilities'

        collection.include_declared = True

        assert (
            binary_report.get_coverage_summary(collection, 0)
            == '1 identified | 0 unidentified | 1 declared | 0 vulnerabilities'
        )

    def test_the_coverage_line_counts_unresolved_declarations(self) -> None:
        collection = _collection(components=[_declared('a', 'b', '1')])
        collection.include_declared = True
        collection.results_by_artifact['app.war'].declared_unresolved = [
            UnresolvedDeclaration('c', 'd', None, 'app.war > x.jar > META-INF/maven/g/x/pom.xml', 'why'),
            UnresolvedDeclaration('e', 'f', '${v}', 'app.war > x.jar > META-INF/maven/g/x/pom.xml', 'why'),
        ]

        assert (
            binary_report.get_coverage_summary(collection, 3)
            == '0 identified | 0 unidentified | 1 declared (2 unresolved) | 3 vulnerabilities'
        )

    def test_unresolved_declarations_are_listed_in_a_stable_order(self) -> None:
        collection = _collection()
        collection.results_by_artifact['app.war'].declared_unresolved = [
            UnresolvedDeclaration('z', 'z', None, 'app.war > b.jar > pom.xml', 'no version'),
            UnresolvedDeclaration('a', 'a', '${v}', 'app.war > b.jar > pom.xml', 'undefined'),
            UnresolvedDeclaration('m', 'm', None, 'app.war > a.jar > pom.xml', 'no version'),
        ]

        entries = binary_report.get_declared_unresolved(collection)

        assert [(e.declared_by, e.coordinate, e.version_expression) for e in entries] == [
            ('app.war > a.jar > pom.xml', 'm:m', '-'),
            ('app.war > b.jar > pom.xml', 'a:a', '${v}'),
            ('app.war > b.jar > pom.xml', 'z:z', '-'),
        ]

    def test_a_finding_on_a_declared_component_knows_it_was_declared(self) -> None:
        collection = _collection(components=[_declared('org.slf4j', 'slf4j-api', '1.7.36', scope='runtime')])
        ctx = _ctx(collection)

        evidence = binary_report.get_detection_evidence(ctx, _detection('org.slf4j:slf4j-api', '1.7.36'))

        assert evidence is not None
        assert evidence.is_declared is True
        assert evidence.is_ambiguous is False
        assert evidence.declared_scope == 'runtime'
        assert evidence.logical_path.endswith('/pom.xml')

    def test_a_declared_finding_gates_the_build(self) -> None:
        # the coordinate is exact; only its presence differs, and the user asked for it
        collection = _collection(components=[_declared('org.slf4j', 'slf4j-api', '1.7.36')])
        ctx = _ctx(collection)

        detection = _detection('org.slf4j:slf4j-api', '1.7.36')

        assert binary_report.is_low_confidence(ctx, detection) is False
        assert binary_report.has_gating_detections(ctx, _scan_results(detection)) is True

    def test_a_shipped_component_is_not_declared(self) -> None:
        collection = _collection(components=[_component(*_LOG4J)])

        detection = _detection('org.apache.logging.log4j:log4j-core', '2.14.1')
        evidence = binary_report.get_detection_evidence(_ctx(collection), detection)

        assert evidence is not None
        assert evidence.is_declared is False

    def test_the_coverage_line_counts_transitives(self) -> None:
        collection = _collection(components=[_declared('a', 'b', '1'), _declared('c', 'd', '2', via='a:b')])
        collection.include_declared = True

        assert (
            binary_report.get_coverage_summary(collection, 0)
            == '0 identified | 0 unidentified | 2 declared (1 transitive) | 0 vulnerabilities'
        )

    def test_a_transitive_finding_names_what_pulled_it_in(self) -> None:
        collection = _collection(components=[_declared('c', 'd', '2', scope='test', via='a:b')])

        evidence = binary_report.get_detection_evidence(_ctx(collection), _detection('c:d', '2'))

        assert evidence is not None
        assert evidence.declared_via == 'a:b'
        assert evidence.presence_summary == 'transitive (test scope) via a:b, not shipped'

    def test_a_direct_declaration_summary(self) -> None:
        collection = _collection(components=[_declared('a', 'b', '1')])

        evidence = binary_report.get_detection_evidence(_ctx(collection), _detection('a:b', '1'))

        assert evidence is not None
        assert evidence.presence_summary == 'declared (compile scope), not shipped'
