"""Regression tests for the findings raised by the pre-merge security review.

Each one is a concrete attack that worked against an earlier revision of this feature. They are grouped here
rather than spread across the suite so a reviewer can see the whole class of "the archive author controls what we
render and what we read" problems in one place.
"""

import hashlib
import io
import os
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import typer
from rich.console import Console

from cycode.cli.files_collector.binary.collector import collect_binary_documents
from cycode.cli.files_collector.binary.identifiers import pom_xml
from cycode.cli.files_collector.binary.identifiers.pom_xml import UnsafeXmlError
from cycode.cli.files_collector.binary.java_extractor import JavaArchiveExtractor
from cycode.cli.files_collector.binary.safe_zip import SafeZip
from cycode.cli.printers.utils import binary_report
from tests.cli.files_collector.binary import fixtures

_LOG4J_VULNERABLE = ('org.apache.logging.log4j', 'log4j-core', '2.14.1')
_LOG4J_PATCHED = ('org.apache.logging.log4j', 'log4j-core', '2.17.1')


def _maven_jar(group: str, artifact: str, version: str) -> bytes:
    return fixtures.archive_bytes(
        files={fixtures.pom_properties_entry_name(group, artifact): fixtures.pom_properties(group, artifact, version)}
    )


def _write(tmp_path: Path, name: str, content: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(content)
    return str(path)


@pytest.mark.filterwarnings('ignore:Duplicate name:UserWarning')
class TestDuplicateEntryNames:
    """A crafted archive must not be able to hide a vulnerable jar behind a patched one of the same name.

    ``ZipFile.open(name)`` resolves through a dict of name -> ZipInfo in which the *last* duplicate wins, so
    reading by name let an artifact author decide which of two same-named entries we actually digested. The
    vulnerable copy was never read, and the scan came back clean.
    """

    def _evasion_war(self) -> bytes:
        vulnerable = _maven_jar(*_LOG4J_VULNERABLE)
        patched = _maven_jar(*_LOG4J_PATCHED)

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('WEB-INF/web.xml', '<web-app/>')
            archive.writestr('WEB-INF/lib/log4j-core.jar', vulnerable)
            archive.writestr('WEB-INF/lib/log4j-core.jar', patched)

        return buffer.getvalue()

    def test_both_duplicates_are_read_from_their_own_records(self, tmp_path: Path) -> None:
        vulnerable = _maven_jar(*_LOG4J_VULNERABLE)
        patched = _maven_jar(*_LOG4J_PATCHED)
        path = _write(tmp_path, 'evasion.war', self._evasion_war())

        extractor = JavaArchiveExtractor()
        result = extractor.identify(extractor.extract(path))

        digests = {component.sha1 for component in result.components}
        assert hashlib.sha1(vulnerable, usedforsecurity=False).hexdigest() in digests
        assert hashlib.sha1(patched, usedforsecurity=False).hexdigest() in digests

    def test_the_vulnerable_version_is_still_reported(self, tmp_path: Path) -> None:
        path = _write(tmp_path, 'evasion.war', self._evasion_war())

        extractor = JavaArchiveExtractor()
        result = extractor.identify(extractor.extract(path))
        versions = {component.version for component in result.components}

        # the whole point: a duplicate name must not be able to suppress the vulnerable copy
        assert '2.14.1' in versions
        assert '2.17.1' in versions

    def test_each_entry_reports_its_own_digest(self, tmp_path: Path) -> None:
        path = _write(tmp_path, 'evasion.war', self._evasion_war())

        with SafeZip.open(path) as archive:
            entries = [entry for entry in archive.entries() if entry.name.endswith('.jar')]
            digests = [archive.read(entry).sha1 for entry in entries]

        assert len(entries) == 2
        assert digests[0] != digests[1], 'both duplicates resolved to the same bytes'


class TestUntrustedTextIsSanitisedForDisplay:
    """Entry names, manifest values and coordinates are authored by whoever built the artifact."""

    def test_rich_markup_is_neutralised(self) -> None:
        hostile = 'app.jar > BOOT-INF/lib/[link=javascript:alert(1)]lib[/link].jar'

        rendered = binary_report.for_display(hostile)

        # rich neutralises a tag by backslash-escaping its opening bracket
        assert r'\[link=' in rendered
        assert r'\[/link]' in rendered

    def test_a_hostile_name_survives_an_html_export_without_becoming_a_link(self) -> None:
        # --export-type html writes this to a file a security engineer opens, or CI publishes as an artifact
        hostile = 'lib/[link=javascript:alert(document.domain)]click[/link].jar'
        console = Console(file=io.StringIO(), record=True, width=200, force_terminal=False)

        console.print(f'  {binary_report.for_display(hostile)}')
        html = console.export_html()

        assert 'javascript:' not in html
        assert '<a ' not in html

    @pytest.mark.parametrize(
        'control',
        ['\x1b[2J', '\x1b[31m', '\n', '\r', '\x07', '\x9b'],
    )
    def test_control_characters_are_stripped(self, control: str) -> None:
        rendered = binary_report.for_display(f'lib/evil{control}name.jar')

        assert control not in rendered

    def test_a_forged_coverage_line_cannot_be_injected(self) -> None:
        # the coverage line is this feature's core claim; an artifact must not be able to forge one
        hostile = 'x.jar\n\n99 identified | 0 unidentified | 0 vulnerabilities\n'

        rendered = binary_report.for_display(hostile)

        assert '\n' not in rendered

    def test_an_absurdly_long_name_is_truncated(self) -> None:
        rendered = binary_report.for_display('a' * 5000)

        assert len(rendered) < 250

    def test_an_ordinary_name_is_left_readable(self) -> None:
        ordinary = 'payments.war > WEB-INF/lib/log4j-core-2.14.1.jar'

        assert binary_report.for_display(ordinary) == ordinary

    def test_the_bom_keeps_the_true_name(self, tmp_path: Path) -> None:
        # sanitisation is presentation only; the uploaded document must describe what is really there
        hostile_name = 'WEB-INF/lib/[weird]name.jar'
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('WEB-INF/web.xml', '<web-app/>')
            archive.writestr(hostile_name, _maven_jar(*_LOG4J_VULNERABLE))

        path = _write(tmp_path, 'app.war', buffer.getvalue())
        extractor = JavaArchiveExtractor()
        result = extractor.identify(extractor.extract(path))

        assert any('[weird]name.jar' in component.logical_path for component in result.components)


class TestKeepBomDoesNotFollowSymlinks:
    """The scanned tree is untrusted: an unpacked vendor drop can plant a symlink at the output path."""

    @pytest.fixture
    def mock_ctx(self) -> typer.Context:
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = {'progress_bar': None, 'binary_max_depth': 3, 'keep_bom': True, 'monitor': False}
        return ctx

    @pytest.mark.skipif(os.name == 'nt', reason='symlink semantics and O_NOFOLLOW differ on Windows')
    def test_a_symlinked_output_path_is_refused(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        drop = tmp_path / 'drop'
        drop.mkdir()
        artifact = drop / 'app.war'
        artifact.write_bytes(fixtures.war_bytes(libraries={'guava.jar': _maven_jar('com.google.guava', 'g', '1')}))

        victim = tmp_path / 'precious.txt'
        victim.write_text('do not overwrite me')
        (drop / 'app.war.bom.json').symlink_to(victim)

        collect_binary_documents(mock_ctx, (str(drop),))

        # the scan still succeeds; the planted target is untouched
        assert victim.read_text() == 'do not overwrite me'

    def test_an_ordinary_path_is_still_written(self, mock_ctx: typer.Context, tmp_path: Path) -> None:
        artifact = tmp_path / 'app.war'
        artifact.write_bytes(fixtures.war_bytes(libraries={'guava.jar': _maven_jar('com.google.guava', 'g', '1')}))

        collect_binary_documents(mock_ctx, (str(artifact),))

        assert (tmp_path / 'app.war.bom.json').exists()


class TestXmlEncodingBypass:
    """A byte-level DOCTYPE guard is bypassable; the guard now runs on decoded text."""

    _BILLION_LAUGHS = (
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]>'
        '<project><artifactId>&lol2;</artifactId></project>'
    )

    def test_a_utf16_encoded_declaration_is_refused(self) -> None:
        # expat sniffs the byte-order mark and would parse the DTD that a bytes-level pattern never matched
        payload = self._BILLION_LAUGHS.encode('utf-16')

        with pytest.raises(UnsafeXmlError, match=r'not valid UTF-8|document type or entity declaration'):
            pom_xml.parse_xml(payload)

    def test_a_utf16_hostile_pom_yields_no_edges(self) -> None:
        assert pom_xml.parse_dependencies(self._BILLION_LAUGHS.encode('utf-16')) == []

    def test_a_utf8_bom_is_still_accepted(self) -> None:
        pom = (
            '<project><dependencies>'
            '<dependency><groupId>a</groupId><artifactId>b</artifactId></dependency>'
            '</dependencies></project>'
        )

        assert [d.coordinate_key for d in pom_xml.parse_dependencies(pom.encode('utf-8-sig'))] == ['a:b']
