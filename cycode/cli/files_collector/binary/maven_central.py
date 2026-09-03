"""Tier 2 against Maven Central: an unidentified archive looked up by the SHA-1 of its bytes.

Opt-in, because it is the one step in this feature that sends anything about the artifact off the machine. What
leaves is a digest, never the archive, but a digest still reveals which jars a customer ships, and plenty of build
environments have no egress to a third party at all. The Cycode backend index replaces this behind the same seam
when it exists; nothing that calls a ``DigestResolver`` has to change.

A hit is exact: the bytes on disk are the bytes Maven Central published under that coordinate. When one digest maps
to several coordinates -- a relocated artifact republished byte-for-byte under a new group -- the index's own
ranking is taken, and the alternatives are logged rather than guessed between.
"""

import logging
from typing import Optional
from urllib.parse import quote

import requests

from cycode.cli import consts
from cycode.cli.files_collector.binary.declared import PomFetch, PomSource, is_safe_coordinate
from cycode.cli.files_collector.binary.resolver import DigestResolver
from cycode.cyclient.cycode_client_base import get_http_session
from cycode.cyclient.headers import get_cli_user_agent

logger = logging.getLogger(__name__)

_SHA1_FIELD = '1'
_ATTEMPTS_PER_DIGEST = 2  # the index is intermittently slow; one retry, never a storm. Pom fetches share it


def _purl_of(group: str, artifact: str, version: str) -> str:
    return f'pkg:maven/{group}/{artifact}@{version}'


def _coordinates_from(document: dict) -> Optional[tuple[str, str, str]]:
    group, artifact, version = document.get('g'), document.get('a'), document.get('v')
    if not group or not artifact or not version:
        return None

    return str(group), str(artifact), str(version)


class MavenCentralDigestResolver(DigestResolver):
    """One request per digest: the search API does not return the digest it matched, so a batched query would
    come back as an unordered pile of coordinates with no way to hand each one back to its archive.

    search.maven.org answers a hit or a miss in well under a second but is intermittently slow, so a timeout is
    retried once and then counted against that digest while the run carries on. A connection-level failure - DNS,
    refused, TLS - will not fix itself within the run, so it stops the run and every remaining digest counts as
    failed. Any failed digest at all makes the resolver report itself unavailable: the results are partial for
    those digests, and the warning says how many and why.
    """

    def __init__(
        self,
        session: Optional[requests.Session] = None,
        search_url: str = consts.BINARY_MAVEN_CENTRAL_SEARCH_URL,
        timeout_in_seconds: float = consts.BINARY_DIGEST_LOOKUP_TIMEOUT_IN_SECONDS,
    ) -> None:
        self._session = session
        self._search_url = search_url
        self._timeout = timeout_in_seconds
        self._asked = 0
        self._failed = 0
        self._last_error: Optional[str] = None
        self._aborted = False

    @property
    def available(self) -> bool:
        return self._failed == 0

    @property
    def unavailability_reason(self) -> str:
        return (
            f'Maven Central lookup failed for {self._failed} of {self._asked} digests ({self._last_error}); '
            f'those were not resolved.'
        )

    def resolve(self, digests: list[str]) -> dict[str, str]:
        resolved: dict[str, str] = {}
        for index, digest in enumerate(digests):
            if self._aborted:
                remaining = len(digests) - index
                self._asked += remaining
                self._failed += remaining
                break

            self._asked += 1
            purl = self._lookup(digest.lower())
            if purl:
                resolved[digest] = purl

        logger.debug(
            'Resolved digests on Maven Central, %s',
            {'asked': len(digests), 'resolved': len(resolved), 'failed_so_far': self._failed},
        )
        return resolved

    def _lookup(self, digest: str) -> Optional[str]:
        query = quote(f'{_SHA1_FIELD}:"{digest}"', safe='')
        url = f'{self._search_url}?q={query}&rows=5&wt=json'

        body = None
        for attempt in range(_ATTEMPTS_PER_DIGEST):
            try:
                response = self._get_session().get(
                    url, headers={'User-Agent': get_cli_user_agent()}, timeout=self._timeout
                )
                response.raise_for_status()
                body = response.json()
                break
            except requests.Timeout as e:
                self._last_error = str(e) or e.__class__.__name__
                if attempt + 1 < _ATTEMPTS_PER_DIGEST:
                    logger.debug('Maven Central lookup timed out, retrying once, %s', {'digest': digest})
            except requests.ConnectionError as e:
                self._last_error = str(e) or e.__class__.__name__
                self._aborted = True
                break
            except (requests.RequestException, ValueError) as e:
                # ValueError covers a non-JSON body, which is what a captive portal or a proxy error page returns
                self._last_error = str(e) or e.__class__.__name__
                break

        if body is None:
            self._failed += 1
            logger.warning('Maven Central lookup failed, %s', {'digest': digest, 'error': self._last_error})
            return None

        section = body.get('response') if isinstance(body, dict) else None
        documents = section.get('docs', []) if isinstance(section, dict) else []
        candidates = [purl for purl in (_coordinates_from(d) for d in documents if isinstance(d, dict)) if purl]
        if not candidates:
            return None

        if len(candidates) > 1:
            logger.debug(
                'A digest is published under several coordinates; taking the first, %s',
                {'digest': digest, 'coordinates': [_purl_of(*c) for c in candidates]},
            )

        return _purl_of(*candidates[0])

    def _get_session(self) -> requests.Session:
        if self._session is None:
            self._session = get_http_session()

        return self._session


class MavenCentralPomSource(PomSource):
    """Parent and imported poms for ``--include-declared``, read from the Maven Central repository itself.

    What leaves the machine is a public coordinate such as ``org.apache:apache:30``, never anything from inside the
    artifact. The same transport rules as the digest lookup apply: one retry on a timeout, an abort for the rest of
    the run on a connection-level failure, and a body cap so a hostile mirror configured through a proxy cannot
    feed the parser an unbounded document.
    """

    def __init__(
        self,
        session: Optional[requests.Session] = None,
        repository_url: str = consts.BINARY_MAVEN_CENTRAL_REPOSITORY_URL,
        timeout_in_seconds: float = consts.BINARY_DIGEST_LOOKUP_TIMEOUT_IN_SECONDS,
        max_size_in_bytes: int = consts.BINARY_POM_MAX_SIZE_IN_BYTES,
    ) -> None:
        self._session = session
        self._repository_url = repository_url.rstrip('/')
        self._timeout = timeout_in_seconds
        self._max_size = max_size_in_bytes
        self._aborted: Optional[str] = None

    def fetch(self, group: str, artifact: str, version: str) -> PomFetch:
        coordinate = f'{group}:{artifact}:{version}'
        if not is_safe_coordinate(group, artifact, version):
            return PomFetch(failure=f'{coordinate} is not a valid Maven coordinate')

        if self._aborted:
            return PomFetch(failure=f'{coordinate} not fetched: Maven Central is unreachable ({self._aborted})')

        url = f'{self._repository_url}/{group.replace(".", "/")}/{artifact}/{version}/{artifact}-{version}.pom'
        last_error: Optional[str] = None
        for attempt in range(_ATTEMPTS_PER_DIGEST):
            try:
                with self._get_session().get(
                    url, headers={'User-Agent': get_cli_user_agent()}, timeout=self._timeout, stream=True
                ) as response:
                    if response.status_code == requests.codes.not_found:
                        return PomFetch(failure=f'{coordinate} is not on Maven Central')

                    response.raise_for_status()
                    return self._read_bounded(response, coordinate)
            except requests.Timeout as e:
                last_error = str(e) or e.__class__.__name__
                if attempt + 1 < _ATTEMPTS_PER_DIGEST:
                    logger.debug('Maven Central pom fetch timed out, retrying once, %s', {'coordinate': coordinate})
            except requests.ConnectionError as e:
                last_error = str(e) or e.__class__.__name__
                self._aborted = last_error
                break
            except requests.RequestException as e:
                last_error = str(e) or e.__class__.__name__
                break

        logger.warning('Maven Central pom fetch failed, %s', {'coordinate': coordinate, 'error': last_error})
        return PomFetch(failure=f'{coordinate} fetch from Maven Central failed ({last_error})')

    def _read_bounded(self, response: requests.Response, coordinate: str) -> PomFetch:
        chunks = []
        received = 0
        for chunk in response.iter_content(chunk_size=64 * 1024):
            received += len(chunk)
            if received > self._max_size:
                return PomFetch(failure=f'{coordinate} exceeds {self._max_size} bytes and was not read')

            chunks.append(chunk)

        return PomFetch(payload=b''.join(chunks))

    def _get_session(self) -> requests.Session:
        if self._session is None:
            self._session = get_http_session()

        return self._session
