"""Tier 2: resolving a digest to a coordinate.

The Cycode index this is designed for does not exist yet, so the default is a no-op implementation. That is
deliberate rather than incomplete: ``NullDigestResolver`` reporting ``available = False`` exercises the exact
degradation path the product promises - the warning, the coverage counters, the partial marker - from day one. The
path is therefore tested and proven in production before that index ever arrives, instead of being written blind
alongside it. ``MavenCentralDigestResolver`` is the opt-in implementation that exists today.
"""

from abc import ABC, abstractmethod


class DigestResolver(ABC):
    @abstractmethod
    def resolve(self, digests: list[str]) -> dict[str, str]:
        """Map sha1 to purl. Missing keys mean unresolved. Never raises."""

    @property
    @abstractmethod
    def available(self) -> bool:
        """False when resolution could not be attempted or did not complete, which makes the results partial."""

    @property
    def unavailability_reason(self) -> str:
        """One sentence for the degradation warning, read only when ``available`` is False."""
        return 'Digest lookup, which could identify the rest, is not available.'


class NullDigestResolver(DigestResolver):
    """The default. The Cycode digest index lands behind this seam when the backend endpoint exists."""

    def resolve(self, digests: list[str]) -> dict[str, str]:
        return {}

    @property
    def available(self) -> bool:
        return False

    @property
    def unavailability_reason(self) -> str:
        return (
            'Digest lookup, which could identify the rest, is not available in this release; '
            '--maven-central looks unidentified archives up by SHA-1 on search.maven.org.'
        )
