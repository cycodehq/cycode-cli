"""``MavenCentralDigestResolver`` against a mocked search.maven.org. No request here ever leaves the process."""

import json
from pathlib import Path

import pytest
import requests
import responses

from cycode.cli import consts
from cycode.cli.files_collector.binary.declared import DeclaredDependencyResolver
from cycode.cli.files_collector.binary.java_extractor import JavaArchiveExtractor
from cycode.cli.files_collector.binary.maven_central import MavenCentralDigestResolver, MavenCentralPomSource
from tests.cli.files_collector.binary import fixtures

_GUAVA_SHA1 = 'bd41a290787b5301e63929676d792c507bbc00ae'
_UNKNOWN_SHA1 = '0' * 40
_ACTIVATION_SHA1 = 'a' * 40


def _search_body(*documents: tuple[str, str, str]) -> dict:
    docs = [{'id': f'{g}:{a}:{v}', 'g': g, 'a': a, 'v': v, 'p': 'jar'} for g, a, v in documents]
    return {'responseHeader': {'status': 0}, 'response': {'numFound': len(docs), 'start': 0, 'docs': docs}}


def _register(digest: str, body: dict, status: int = 200) -> None:
    responses.add(
        responses.GET,
        consts.BINARY_MAVEN_CENTRAL_SEARCH_URL,
        match=[responses.matchers.query_param_matcher({'q': f'1:"{digest}"', 'rows': '5', 'wt': 'json'})],
        json=body,
        status=status,
    )


class TestResolve:
    @responses.activate
    def test_a_hit_is_an_exact_purl(self) -> None:
        _register(_GUAVA_SHA1, _search_body(('com.google.guava', 'guava', '27.0.1-jre')))
        resolver = MavenCentralDigestResolver(session=requests.Session())

        assert resolver.resolve([_GUAVA_SHA1]) == {_GUAVA_SHA1: 'pkg:maven/com.google.guava/guava@27.0.1-jre'}
        assert resolver.available is True

    @responses.activate
    def test_a_miss_is_left_out_rather_than_guessed(self) -> None:
        _register(_UNKNOWN_SHA1, _search_body())
        resolver = MavenCentralDigestResolver(session=requests.Session())

        assert resolver.resolve([_UNKNOWN_SHA1]) == {}
        # nothing went wrong: the archive is simply not on Maven Central, and that is not a partial result
        assert resolver.available is True

    @responses.activate
    def test_the_digest_is_sent_in_lower_case(self) -> None:
        _register(_GUAVA_SHA1, _search_body(('com.google.guava', 'guava', '27.0.1-jre')))
        resolver = MavenCentralDigestResolver(session=requests.Session())

        resolved = resolver.resolve([_GUAVA_SHA1.upper()])

        # the caller's key is preserved so it can be mapped back to the archive it came from
        assert list(resolved) == [_GUAVA_SHA1.upper()]

    @responses.activate
    def test_a_relocated_artifact_takes_the_index_ranking(self) -> None:
        _register(
            _ACTIVATION_SHA1,
            _search_body(
                ('com.sun.activation', 'javax.activation', '1.2.0'), ('javax.activation', 'activation', '1.2.0')
            ),
        )
        resolver = MavenCentralDigestResolver(session=requests.Session())

        assert resolver.resolve([_ACTIVATION_SHA1]) == {
            _ACTIVATION_SHA1: 'pkg:maven/com.sun.activation/javax.activation@1.2.0'
        }

    @responses.activate
    def test_a_document_missing_a_coordinate_is_skipped(self) -> None:
        responses.add(
            responses.GET,
            consts.BINARY_MAVEN_CENTRAL_SEARCH_URL,
            json={'response': {'docs': [{'g': 'x', 'a': 'y'}, {'g': 'com.acme', 'a': 'lib', 'v': '1.0'}]}},
        )
        resolver = MavenCentralDigestResolver(session=requests.Session())

        assert resolver.resolve([_GUAVA_SHA1]) == {_GUAVA_SHA1: 'pkg:maven/com.acme/lib@1.0'}

    @responses.activate
    def test_the_user_agent_identifies_the_cli(self) -> None:
        _register(_GUAVA_SHA1, _search_body())
        MavenCentralDigestResolver(session=requests.Session()).resolve([_GUAVA_SHA1])

        assert responses.calls[0].request.headers['User-Agent'].startswith('CycodeCLI/')


class TestFailure:
    @responses.activate
    def test_a_connection_error_stops_the_run_and_makes_results_partial(self) -> None:
        _register(_GUAVA_SHA1, _search_body(('com.google.guava', 'guava', '27.0.1-jre')))
        responses.add(
            responses.GET,
            consts.BINARY_MAVEN_CENTRAL_SEARCH_URL,
            match=[responses.matchers.query_param_matcher({'q': f'1:"{_UNKNOWN_SHA1}"', 'rows': '5', 'wt': 'json'})],
            body=requests.ConnectionError('name resolution failed'),
        )
        resolver = MavenCentralDigestResolver(session=requests.Session())

        resolved = resolver.resolve([_GUAVA_SHA1, _UNKNOWN_SHA1, _ACTIVATION_SHA1])

        # what was resolved before the failure is kept; the digest after it was never asked for
        assert resolved == {_GUAVA_SHA1: 'pkg:maven/com.google.guava/guava@27.0.1-jre'}
        assert len(responses.calls) == 2
        assert resolver.available is False
        assert 'failed for 2 of 3 digests' in resolver.unavailability_reason
        assert 'name resolution failed' in resolver.unavailability_reason

    @responses.activate
    def test_a_timeout_is_retried_once_and_the_run_continues(self) -> None:
        # the index is intermittently slow: one slow digest must not cost the two hundred behind it
        responses.add(
            responses.GET,
            consts.BINARY_MAVEN_CENTRAL_SEARCH_URL,
            match=[responses.matchers.query_param_matcher({'q': f'1:"{_UNKNOWN_SHA1}"', 'rows': '5', 'wt': 'json'})],
            body=requests.Timeout('slow'),
        )
        _register(_GUAVA_SHA1, _search_body(('com.google.guava', 'guava', '27.0.1-jre')))
        resolver = MavenCentralDigestResolver(session=requests.Session())

        resolved = resolver.resolve([_UNKNOWN_SHA1, _GUAVA_SHA1])

        assert resolved == {_GUAVA_SHA1: 'pkg:maven/com.google.guava/guava@27.0.1-jre'}
        assert len(responses.calls) == 3  # two attempts for the slow digest, one for the hit
        assert resolver.available is False
        assert 'failed for 1 of 2 digests' in resolver.unavailability_reason

    @responses.activate
    def test_a_timeout_that_succeeds_on_retry_is_not_a_failure(self) -> None:
        responses.add(responses.GET, consts.BINARY_MAVEN_CENTRAL_SEARCH_URL, body=requests.Timeout('slow'))
        responses.add(
            responses.GET,
            consts.BINARY_MAVEN_CENTRAL_SEARCH_URL,
            json=_search_body(('com.google.guava', 'guava', '27.0.1-jre')),
        )
        resolver = MavenCentralDigestResolver(session=requests.Session())

        resolved = resolver.resolve([_GUAVA_SHA1])

        assert resolved == {_GUAVA_SHA1: 'pkg:maven/com.google.guava/guava@27.0.1-jre'}
        assert resolver.available is True

    @responses.activate
    def test_a_server_error_counts_against_the_digest_without_a_retry(self) -> None:
        _register(_GUAVA_SHA1, {}, status=503)
        resolver = MavenCentralDigestResolver(session=requests.Session())

        assert resolver.resolve([_GUAVA_SHA1]) == {}
        assert len(responses.calls) == 1
        assert resolver.available is False

    @responses.activate
    def test_a_non_json_body_is_a_failure(self) -> None:
        # a captive portal or a proxy error page answers 200 with HTML
        responses.add(responses.GET, consts.BINARY_MAVEN_CENTRAL_SEARCH_URL, body='<html>sign in</html>')
        resolver = MavenCentralDigestResolver(session=requests.Session())

        assert resolver.resolve([_GUAVA_SHA1]) == {}
        assert resolver.available is False

    @responses.activate
    def test_a_later_call_after_a_connection_error_does_not_retry(self) -> None:
        responses.add(responses.GET, consts.BINARY_MAVEN_CENTRAL_SEARCH_URL, body=requests.ConnectionError('refused'))
        resolver = MavenCentralDigestResolver(session=requests.Session())

        resolver.resolve([_GUAVA_SHA1])
        resolver.resolve([_UNKNOWN_SHA1])

        assert len(responses.calls) == 1
        assert 'failed for 2 of 2 digests' in resolver.unavailability_reason


class TestThroughTheLadder:
    def _write(self, tmp_path: Path, name: str, content: bytes) -> str:
        path = tmp_path / name
        path.write_bytes(content)
        return str(path)

    @responses.activate
    def test_an_anonymous_jar_on_maven_central_is_identified_exactly(self, tmp_path: Path) -> None:
        anonymous = fixtures.archive_bytes(files={'com/google/common/Foo.class': b'\xca\xfe\xba\xbe'})
        responses.add(
            responses.GET,
            consts.BINARY_MAVEN_CENTRAL_SEARCH_URL,
            json=_search_body(('com.google.guava', 'guava', '27.0.1-jre')),
        )
        extractor = JavaArchiveExtractor(resolver=MavenCentralDigestResolver(session=requests.Session()))
        path = self._write(tmp_path, 'app.war', fixtures.war_bytes(libraries={'mystery.jar': anonymous}))

        result = extractor.identify(extractor.extract(path))

        assert [c.purl for c in result.components] == ['pkg:maven/com.google.guava/guava@27.0.1-jre']
        assert result.components[0].evidence == 'digest'
        assert result.components[0].confidence == 'exact'
        assert result.unidentified == []
        assert result.resolver_available is True
        assert result.resolver_unavailability_reason is None

    @responses.activate
    def test_a_failure_is_carried_on_the_result(self, tmp_path: Path) -> None:
        anonymous = fixtures.archive_bytes(files={'com/acme/Foo.class': b'\xca\xfe\xba\xbe'})
        responses.add(responses.GET, consts.BINARY_MAVEN_CENTRAL_SEARCH_URL, body=requests.ConnectionError('offline'))
        extractor = JavaArchiveExtractor(resolver=MavenCentralDigestResolver(session=requests.Session()))
        path = self._write(tmp_path, 'app.war', fixtures.war_bytes(libraries={'mystery.jar': anonymous}))

        result = extractor.identify(extractor.extract(path))

        assert len(result.unidentified) == 1
        assert result.resolver_available is False
        assert 'offline' in result.resolver_unavailability_reason

    @responses.activate
    def test_metadata_wins_and_maven_central_is_not_asked(self, tmp_path: Path) -> None:
        extractor = JavaArchiveExtractor(resolver=MavenCentralDigestResolver(session=requests.Session()))
        path = self._write(tmp_path, 'guava.jar', fixtures.library_jar('com.google.guava', 'guava', '31.1-jre'))

        result = extractor.identify(extractor.extract(path))

        assert result.components[0].evidence == 'pom.properties'
        assert len(responses.calls) == 0


@pytest.mark.parametrize('body', [json.dumps([]), json.dumps({'response': 'nope'})])
@responses.activate
def test_an_unexpected_json_shape_is_a_miss_not_a_crash(body: str) -> None:
    responses.add(responses.GET, consts.BINARY_MAVEN_CENTRAL_SEARCH_URL, body=body, content_type='application/json')
    resolver = MavenCentralDigestResolver(session=requests.Session())

    assert resolver.resolve([_GUAVA_SHA1]) == {}
    assert resolver.available is True


_REPOSITORY = 'https://repo.test/maven2'
_APACHE_POM_URL = f'{_REPOSITORY}/org/apache/apache/30/apache-30.pom'
_APACHE_POM = b'<project><groupId>org.apache</groupId><artifactId>apache</artifactId><version>30</version></project>'


def _pom_source(**kwargs: object) -> MavenCentralPomSource:
    return MavenCentralPomSource(session=requests.Session(), repository_url=_REPOSITORY, **kwargs)


class TestPomSource:
    @responses.activate
    def test_a_pom_is_fetched_from_its_repository_path(self) -> None:
        responses.add(responses.GET, _APACHE_POM_URL, body=_APACHE_POM, status=200)

        fetched = _pom_source().fetch('org.apache', 'apache', '30')

        assert fetched.payload == _APACHE_POM
        assert fetched.failure is None

    @responses.activate
    def test_a_missing_pom_is_a_miss_with_a_reason(self) -> None:
        responses.add(responses.GET, _APACHE_POM_URL, status=404)

        fetched = _pom_source().fetch('org.apache', 'apache', '30')

        assert fetched.payload is None
        assert fetched.failure == 'org.apache:apache:30 is not on Maven Central'

    @responses.activate
    def test_a_timeout_is_retried_once_then_reported(self) -> None:
        responses.add(responses.GET, _APACHE_POM_URL, body=requests.Timeout('slow'))
        responses.add(responses.GET, _APACHE_POM_URL, body=_APACHE_POM, status=200)

        assert _pom_source().fetch('org.apache', 'apache', '30').payload == _APACHE_POM
        assert len(responses.calls) == 2

    @responses.activate
    def test_two_timeouts_are_a_failure(self) -> None:
        responses.add(responses.GET, _APACHE_POM_URL, body=requests.Timeout('slow'))
        responses.add(responses.GET, _APACHE_POM_URL, body=requests.Timeout('slow'))

        fetched = _pom_source().fetch('org.apache', 'apache', '30')

        assert fetched.payload is None
        assert 'fetch from Maven Central failed' in fetched.failure

    @responses.activate
    def test_a_connection_failure_stops_further_fetches(self) -> None:
        responses.add(responses.GET, _APACHE_POM_URL, body=requests.ConnectionError('refused'))
        source = _pom_source()

        first = source.fetch('org.apache', 'apache', '30')
        second = source.fetch('org.apache', 'apache', '31')

        assert first.payload is None
        assert 'unreachable' in second.failure
        assert len(responses.calls) == 1

    @responses.activate
    def test_a_hostile_coordinate_never_becomes_a_url(self) -> None:
        fetched = _pom_source().fetch('../../etc', 'passwd', '1')

        assert fetched.payload is None
        assert 'is not a valid Maven coordinate' in fetched.failure
        assert len(responses.calls) == 0

    @responses.activate
    def test_an_oversized_body_is_refused(self) -> None:
        responses.add(responses.GET, _APACHE_POM_URL, body=b'x' * 2048, status=200)

        fetched = _pom_source(max_size_in_bytes=1024).fetch('org.apache', 'apache', '30')

        assert fetched.payload is None
        assert 'exceeds 1024 bytes' in fetched.failure

    @responses.activate
    def test_an_embedded_pom_resolves_its_parent_managed_version_end_to_end(self, tmp_path: Path) -> None:
        parent = (
            b'<project><groupId>org.apache.woden</groupId><artifactId>woden</artifactId><version>1.0M10</version>'
            b'<dependencyManagement><dependencies><dependency>'
            b'<groupId>commons-logging</groupId><artifactId>commons-logging</artifactId><version>1.1.1</version>'
            b'</dependency></dependencies></dependencyManagement></project>'
        )
        responses.add(
            responses.GET, f'{_REPOSITORY}/org/apache/woden/woden/1.0M10/woden-1.0M10.pom', body=parent, status=200
        )
        child = (
            b'<project><parent><groupId>org.apache.woden</groupId><artifactId>woden</artifactId>'
            b'<version>1.0M10</version></parent><artifactId>woden-core</artifactId>'
            b'<dependencies><dependency><groupId>commons-logging</groupId><artifactId>commons-logging</artifactId>'
            b'</dependency></dependencies></project>'
        )
        jar = fixtures.archive_bytes(
            files={
                fixtures.pom_properties_entry_name('org.apache.woden', 'woden-core'): fixtures.pom_properties(
                    'org.apache.woden', 'woden-core', '1.0M10'
                ),
                'META-INF/maven/org.apache.woden/woden-core/pom.xml': child,
            }
        )
        path = tmp_path / 'woden-core.jar'
        path.write_bytes(jar)

        extractor = JavaArchiveExtractor(declared_resolver=DeclaredDependencyResolver(_pom_source()))
        result = extractor.identify(extractor.extract(str(path)))

        assert [c.purl for c in result.declared_components] == ['pkg:maven/commons-logging/commons-logging@1.1.1']
        assert result.declared_unresolved == []
