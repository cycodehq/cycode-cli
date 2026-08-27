"""Tier 2 wiring and the ordering of the identification ladder.

No requests are made here: the shipped resolver is a no-op and the endpoint behind tier 2 does not exist yet, so
these tests drive the seam with a stub. When ``CycodeDigestResolver`` lands in phase 6 it is the stub that gets
replaced with ``responses``, not this ordering.
"""

import hashlib
from pathlib import Path

import pytest

from cycode.cli.files_collector.binary.java_extractor import JavaArchiveExtractor, parse_maven_purl
from cycode.cli.files_collector.binary.resolver import DigestResolver, NullDigestResolver
from tests.cli.files_collector.binary import fixtures

_GUAVA = ('com.google.guava', 'guava', '31.1-jre')


class StubResolver(DigestResolver):
    """Stands in for the backend index. Records what it was asked, so batching can be asserted."""

    def __init__(self, answers: dict, available: bool = True) -> None:
        self._answers = answers
        self._available = available
        self.calls: list[list[str]] = []

    def resolve(self, digests: list[str]) -> dict:
        self.calls.append(list(digests))
        if not self._available:
            return {}

        return {digest: self._answers[digest] for digest in digests if digest in self._answers}

    @property
    def available(self) -> bool:
        return self._available


def _write(tmp_path: Path, name: str, content: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(content)
    return str(path)


def _sha1(payload: bytes) -> str:
    return hashlib.sha1(payload, usedforsecurity=False).hexdigest()


class TestNullDigestResolver:
    def test_it_resolves_nothing_and_says_so(self) -> None:
        resolver = NullDigestResolver()

        assert resolver.resolve(['a' * 40]) == {}
        assert resolver.available is False

    def test_it_is_the_default(self, tmp_path: Path) -> None:
        path = _write(tmp_path, 'app.war', fixtures.war_bytes())
        extractor = JavaArchiveExtractor()

        result = extractor.identify(extractor.extract(path))

        # this is what drives the degradation warning in the printers
        assert result.resolver_available is False


class TestParseMavenPurl:
    def test_a_namespaced_purl(self) -> None:
        coordinates = parse_maven_purl('pkg:maven/com.google.guava/guava@31.1-jre')

        assert (coordinates.group, coordinates.artifact, coordinates.version) == _GUAVA

    def test_a_purl_with_no_namespace(self) -> None:
        coordinates = parse_maven_purl('pkg:maven/widget@1.0')

        assert (coordinates.group, coordinates.artifact, coordinates.version) == ('', 'widget', '1.0')

    def test_qualifiers_and_subpaths_are_ignored(self) -> None:
        coordinates = parse_maven_purl('pkg:maven/com.acme/widget@1.0?type=jar#sub')

        assert coordinates.version == '1.0'

    @pytest.mark.parametrize(
        'purl',
        [None, '', 'pkg:npm/left-pad@1.0.0', 'pkg:maven/com.acme/widget', 'pkg:maven/@1.0', 'not-a-purl'],
    )
    def test_anything_unusable_yields_nothing(self, purl: str) -> None:
        assert parse_maven_purl(purl) is None


class TestTierOrdering:
    def test_a_digest_hit_identifies_a_jar_with_no_metadata(self, tmp_path: Path) -> None:
        anonymous = fixtures.archive_bytes(files={'com/acme/Shim.class': b'\xca\xfe\xba\xbe'})
        war = fixtures.war_bytes(libraries={'stripped.jar': anonymous})
        resolver = StubResolver({_sha1(anonymous): 'pkg:maven/com.google.guava/guava@31.1-jre'})

        extractor = JavaArchiveExtractor(resolver=resolver)
        result = extractor.identify(extractor.extract(_write(tmp_path, 'app.war', war)))

        assert [component.purl for component in result.components] == ['pkg:maven/com.google.guava/guava@31.1-jre']
        assert result.components[0].evidence == 'digest'
        assert result.components[0].confidence == 'exact'
        assert result.unidentified == []

    def test_embedded_metadata_beats_a_digest_hit(self, tmp_path: Path) -> None:
        guava = fixtures.library_jar(*_GUAVA)
        war = fixtures.war_bytes(libraries={'guava.jar': guava})
        resolver = StubResolver({_sha1(guava): 'pkg:maven/wrong/answer@9.9'})

        extractor = JavaArchiveExtractor(resolver=resolver)
        result = extractor.identify(extractor.extract(_write(tmp_path, 'app.war', war)))

        assert result.components[0].purl == 'pkg:maven/com.google.guava/guava@31.1-jre'
        assert result.components[0].evidence == 'pom.properties'
        # tier 1 answered, so the digest was never offered for resolution
        assert resolver.calls == []

    def test_a_digest_hit_beats_the_manifest(self, tmp_path: Path) -> None:
        manifest_only = fixtures.archive_bytes(
            files={'META-INF/MANIFEST.MF': fixtures.manifest(Implementation_Title='guessy', Implementation_Version='1')}
        )
        war = fixtures.war_bytes(libraries={'lib.jar': manifest_only})
        resolver = StubResolver({_sha1(manifest_only): 'pkg:maven/com.google.guava/guava@31.1-jre'})

        extractor = JavaArchiveExtractor(resolver=resolver)
        result = extractor.identify(extractor.extract(_write(tmp_path, 'app.war', war)))

        assert result.components[0].evidence == 'digest'
        assert result.components[0].confidence == 'exact'

    def test_the_manifest_is_the_fallback_when_the_digest_is_unknown(self, tmp_path: Path) -> None:
        manifest_only = fixtures.archive_bytes(
            files={
                'META-INF/MANIFEST.MF': fixtures.manifest(
                    Implementation_Title='guessy', Implementation_Version='1', Implementation_Vendor_Id='com.acme'
                )
            }
        )
        war = fixtures.war_bytes(libraries={'lib.jar': manifest_only})

        extractor = JavaArchiveExtractor(resolver=StubResolver({}))
        result = extractor.identify(extractor.extract(_write(tmp_path, 'app.war', war)))

        assert result.components[0].evidence == 'manifest.mf'
        assert result.components[0].confidence == 'ambiguous'

    def test_one_component_per_digest_across_tiers(self, tmp_path: Path) -> None:
        # a jar carrying both pom.properties and a manifest must not be reported twice
        both = fixtures.library_jar(*_GUAVA)
        war = fixtures.war_bytes(libraries={'guava.jar': both})

        extractor = JavaArchiveExtractor()
        result = extractor.identify(extractor.extract(_write(tmp_path, 'app.war', war)))

        assert len(result.components) == 1


class TestBatching:
    def test_every_unresolved_digest_goes_in_one_request(self, tmp_path: Path) -> None:
        anonymous = [fixtures.archive_bytes(files={f'com/acme/{index}.class': b'x'}) for index in range(3)]
        war = fixtures.war_bytes(libraries={f'lib-{index}.jar': content for index, content in enumerate(anonymous)})
        resolver = StubResolver({})

        extractor = JavaArchiveExtractor(resolver=resolver)
        extractor.identify(extractor.extract(_write(tmp_path, 'app.war', war)))

        assert len(resolver.calls) == 1
        assert sorted(resolver.calls[0]) == sorted(_sha1(content) for content in anonymous)

    def test_an_unavailable_resolver_is_still_asked_and_the_result_says_so(self, tmp_path: Path) -> None:
        # the resolver keeps its own state: a real one that failed on artifact 1 must still be offered artifact 2,
        # otherwise one slow lookup silently switches tier 2 off for the rest of the run
        anonymous = fixtures.archive_bytes(files={'com/acme/Shim.class': b'x'})
        war = fixtures.war_bytes(libraries={'lib.jar': anonymous})
        resolver = StubResolver({_sha1(anonymous): 'pkg:maven/com.acme/thing@1.0'}, available=False)

        extractor = JavaArchiveExtractor(resolver=resolver)
        result = extractor.identify(extractor.extract(_write(tmp_path, 'app.war', war)))

        assert resolver.calls == [[_sha1(anonymous)]]
        assert result.resolver_available is False
        # degradation, not failure: the jar is surfaced rather than dropped
        assert len(result.unidentified) == 1

    def test_nothing_is_sent_when_local_identification_covered_everything(self, tmp_path: Path) -> None:
        # digests of proprietary jars only leave the machine when they have to
        war = fixtures.war_bytes(libraries={'guava.jar': fixtures.library_jar(*_GUAVA)})
        resolver = StubResolver({})

        extractor = JavaArchiveExtractor(resolver=resolver)
        extractor.identify(extractor.extract(_write(tmp_path, 'app.war', war)))

        assert resolver.calls == []
