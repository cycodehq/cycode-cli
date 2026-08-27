"""``MavenCentralDigestResolver`` against a mocked search.maven.org. No request here ever leaves the process."""

import json
from pathlib import Path

import pytest
import requests
import responses

from cycode.cli import consts
from cycode.cli.files_collector.binary.java_extractor import JavaArchiveExtractor
from cycode.cli.files_collector.binary.maven_central import MavenCentralDigestResolver
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
