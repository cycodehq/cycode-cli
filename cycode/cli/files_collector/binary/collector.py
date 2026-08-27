"""Orchestration: artifact paths in, scannable documents out.

This is the only module in the binary package that knows about ``typer.Context``. Everything below it is a pure
function over bytes, which is what makes the extraction and identification logic unit-testable without a network,
an authenticated client, or a CLI invocation.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Optional
from xml.sax.saxutils import escape

import typer

from cycode.cli import consts
from cycode.cli.files_collector.binary import cyclonedx_builder
from cycode.cli.files_collector.binary.base_extractor import CONFIDENCE_AMBIGUOUS, BinaryExtractor, ExtractionResult
from cycode.cli.files_collector.binary.java_extractor import JavaArchiveExtractor
from cycode.cli.files_collector.binary.maven_central import MavenCentralDigestResolver
from cycode.cli.files_collector.binary.resolver import DigestResolver, NullDigestResolver
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_path_by_os
from cycode.cli.utils.progress_bar import ProgressBarSection, ScanProgressBarSection
from cycode.logger import get_logger

logger = get_logger('Binary Collector')

BOM_FILE_NAME = 'bom.json'
POM_FILE_NAME = 'pom.xml'

# the cyclonedx-maven-plugin writes <manifest_dir>/target/bom.json, and we mirror that exactly
BOM_DIRECTORY_NAME = 'target'

_SAFE_ARTIFACT_ID = re.compile(r'[^A-Za-z0-9._-]')

SYNTHETIC_POM_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!-- Synthesised by the Cycode CLI to describe a scanned binary artifact.
     It declares no dependencies: the component inventory lives in target/bom.json beside it. -->
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.cycode.binary</groupId>
  <artifactId>{artifact_id}</artifactId>
  <version>0</version>
  <name>{name}</name>
</project>
"""


def build_artifact_root(artifact_path: str) -> str:
    """The directory the synthesised documents are presented under, derived from the artifact they describe."""
    relative = artifact_path
    if os.path.isabs(artifact_path):
        try:
            relative = os.path.relpath(artifact_path, os.getcwd())
        except ValueError:
            # different drives on Windows; provenance beyond the filename is not recoverable
            relative = os.path.basename(artifact_path)

        if relative.startswith(os.pardir):
            relative = os.path.basename(artifact_path)

    return relative


def build_document_path(artifact_path: str) -> str:
    """Where the synthesised BOM is presented, e.g. 'dist/payments.war/target/bom.json'."""
    return get_path_by_os(os.path.join(build_artifact_root(artifact_path), BOM_DIRECTORY_NAME, BOM_FILE_NAME))


def build_manifest_path(artifact_path: str) -> str:
    """Where the synthesised manifest is presented, e.g. 'dist/payments.war/pom.xml'."""
    return get_path_by_os(os.path.join(build_artifact_root(artifact_path), POM_FILE_NAME))


def build_synthetic_manifest(artifact_name: str) -> str:
    """A minimal pom.xml that gives the BOM the project context the scan service requires.

    Phase 0 established this is not optional. A bom.json that arrives alone is accepted by api/v4/scans/cli -- a
    scan id comes back and the scan completes with no warning -- but produces no detections at all. The identical
    document beside a pom.xml yields the full set, Log4Shell included. The manifest declares no dependencies of its
    own, so every finding still comes from the BOM; it exists purely to make the engine route the document.
    """
    artifact_id = _SAFE_ARTIFACT_ID.sub('-', artifact_name) or 'artifact'
    return SYNTHETIC_POM_TEMPLATE.format(artifact_id=escape(artifact_id), name=escape(artifact_name))


@dataclass
class BinaryCollectionResult:
    documents: list[Document] = field(default_factory=list)
    results_by_artifact: dict[str, ExtractionResult] = field(default_factory=dict)
    failures: dict[str, str] = field(default_factory=dict)

    @property
    def identified_count(self) -> int:
        return sum(len(result.components) for result in self.results_by_artifact.values())

    @property
    def low_confidence_count(self) -> int:
        """Components named by a manifest attribute only. Counted as identified, but a reader must be able to tell."""
        return sum(
            1
            for result in self.results_by_artifact.values()
            for component in result.components
            if component.confidence == CONFIDENCE_AMBIGUOUS
        )

    @property
    def unidentified_count(self) -> int:
        return sum(len(result.unidentified) for result in self.results_by_artifact.values())

    @property
    def resolver_available(self) -> bool:
        return all(result.resolver_available for result in self.results_by_artifact.values())

    @property
    def resolver_unavailability_reason(self) -> Optional[str]:
        """The reason as of the last artifact. One resolver serves the whole run and its counts accumulate, so an
        earlier snapshot would under-report how many digests were affected."""
        reasons = [
            result.resolver_unavailability_reason
            for result in self.results_by_artifact.values()
            if result.resolver_unavailability_reason
        ]
        return reasons[-1] if reasons else None


def get_extractors(resolver: Optional[DigestResolver] = None) -> list[BinaryExtractor]:
    """Registered extractors, in the order they are offered a path.

    .NET, npm and container support arrive as additional entries here rather than as new architecture.
    """
    return [JavaArchiveExtractor(resolver=resolver or NullDigestResolver())]


def get_resolver(ctx: typer.Context) -> DigestResolver:
    """Tier 2 is opt-in: nothing about an artifact leaves the machine unless the user asked for it to."""
    if ctx.obj.get('maven_central'):
        return MavenCentralDigestResolver()

    return NullDigestResolver()


def find_supported_artifacts(paths: tuple[str, ...]) -> list[str]:
    """Every file under the given paths that some extractor claims. Directories are walked."""
    extractors = get_extractors()
    artifacts = []

    for path in paths:
        if os.path.isfile(path):
            candidates = [path]
        else:
            candidates = [
                os.path.join(directory, name) for directory, _, names in os.walk(path) for name in sorted(names)
            ]

        artifacts.extend(
            candidate for candidate in candidates if any(extractor.handles(candidate) for extractor in extractors)
        )

    return artifacts


def collect_binary_documents(
    ctx: typer.Context,
    paths: tuple[str, ...],
    stop_on_error: bool = False,
    progress_bar_section: Optional['ProgressBarSection'] = ScanProgressBarSection.PREPARE_LOCAL_FILES,
) -> BinaryCollectionResult:
    """Extract, identify and synthesise one CycloneDX document per artifact.

    A failure on one artifact does not stop the others unless ``--stop-on-error`` was given: a sweep over an
    artifact repository should report what it could read, not abort on the first unreadable file.

    The scan and report flows drive different progress bars, so the section to advance is passed in rather than
    assumed. Pass None when the caller has already completed that section -- as the path scan has by the time
    --include-binaries runs -- because reopening a finished section breaks the bar.
    """
    max_depth = ctx.obj.get('binary_max_depth', consts.BINARY_MAX_DEPTH)
    keep_bom = ctx.obj.get('keep_bom', False)

    progress_bar = ctx.obj.get('progress_bar') if progress_bar_section is not None else None
    artifacts = find_supported_artifacts(paths)

    logger.debug('Collecting binary artifacts, %s', {'count': len(artifacts), 'max_depth': max_depth})
    if progress_bar and artifacts:
        progress_bar.set_section_length(progress_bar_section, len(artifacts))

    collection = BinaryCollectionResult()
    # one resolver for the whole run, so a transport failure on the first artifact is not retried on every other
    extractors = get_extractors(get_resolver(ctx))

    for artifact_path in artifacts:
        try:
            documents, result = _collect_one(artifact_path, extractors, max_depth, keep_bom)
        except Exception as e:
            logger.debug('Failed to read an artifact, %s', {'path': artifact_path}, exc_info=e)
            collection.failures[artifact_path] = str(e)
            if stop_on_error:
                raise
        else:
            collection.documents.extend(documents)
            collection.results_by_artifact[artifact_path] = result

        if progress_bar:
            progress_bar.update(progress_bar_section)

    return collection


def _collect_one(
    artifact_path: str,
    extractors: list[BinaryExtractor],
    max_depth: int,
    keep_bom: bool,
) -> tuple[list[Document], ExtractionResult]:
    extractor = next(extractor for extractor in extractors if extractor.handles(artifact_path))

    entries = extractor.extract(artifact_path, max_depth)
    result = extractor.identify(entries)

    artifact_name = os.path.basename(artifact_path)
    content = cyclonedx_builder.build_bom_json(artifact_name, result)
    document_path = build_document_path(artifact_path)

    logger.debug(
        'Synthesised a BOM, %s',
        {
            'path': document_path,
            'components': len(result.components),
            'unidentified': len(result.unidentified),
            'archives_opened': result.archives_opened,
        },
    )

    if keep_bom:
        _write_bom_beside_artifact(artifact_path, content)

    documents = [
        Document(document_path, content, is_git_diff_format=False, absolute_path=artifact_path),
        Document(
            build_manifest_path(artifact_path),
            build_synthetic_manifest(artifact_name),
            is_git_diff_format=False,
            absolute_path=artifact_path,
        ),
    ]

    return documents, result


def _write_bom_beside_artifact(artifact_path: str, content: str) -> Optional[str]:
    """``--keep-bom``: the synthesised document, on disk, for inspection and audit."""
    output_path = f'{artifact_path}.{BOM_FILE_NAME}'
    try:
        # O_NOFOLLOW: the tree being scanned is untrusted by this feature's own threat model, and an unpacked
        # vendor drop can carry a symlink at this exact path pointing anywhere the user can write
        descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            handle.write(content)
    except OSError as e:
        # an unwritable directory is not a reason to fail a scan that has otherwise succeeded
        logger.warning('Could not write the BOM, %s', {'path': output_path, 'error': str(e)})
        return None

    logger.debug('Wrote the synthesised BOM, %s', {'path': output_path})
    return output_path
