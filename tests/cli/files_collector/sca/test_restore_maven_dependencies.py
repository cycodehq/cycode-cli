import json
from unittest.mock import MagicMock, patch

from cycode.cli.files_collector.sca.maven.restore_maven_dependencies import (
    RestoreMavenDependencies,
    _has_dependency_graph,
)
from cycode.cli.models import Document


class TestHasDependencyGraph:
    def test_returns_false_when_content_is_none(self) -> None:
        assert _has_dependency_graph(None) is False

    def test_returns_false_when_content_is_empty_string(self) -> None:
        assert _has_dependency_graph('') is False

    def test_returns_false_when_dependencies_section_is_missing(self) -> None:
        content = json.dumps({'components': [{'name': 'foo'}]})
        assert _has_dependency_graph(content) is False

    def test_returns_false_when_all_dependencies_have_empty_depends_on(self) -> None:
        content = json.dumps({'dependencies': [{'ref': 'pkg:maven/foo/bar@1.0', 'dependsOn': []}]})
        assert _has_dependency_graph(content) is False

    def test_returns_false_when_dependencies_list_is_empty(self) -> None:
        content = json.dumps({'dependencies': []})
        assert _has_dependency_graph(content) is False

    def test_returns_true_when_at_least_one_dependency_has_depends_on(self) -> None:
        content = json.dumps(
            {
                'dependencies': [
                    {'ref': 'pkg:maven/com.example/root@1.0', 'dependsOn': ['pkg:maven/io.netty/netty-all@4.1.0']},
                    {'ref': 'pkg:maven/io.netty/netty-all@4.1.0', 'dependsOn': []},
                ]
            }
        )
        assert _has_dependency_graph(content) is True

    def test_returns_false_when_content_is_invalid_json(self) -> None:
        assert _has_dependency_graph('not valid json {{{') is False


class TestRestoreMavenDependenciesFallback:
    def _make_instance(self) -> RestoreMavenDependencies:
        ctx = MagicMock()
        ctx.obj = {}
        return RestoreMavenDependencies(ctx=ctx, is_git_diff=False, command_timeout=60)

    def test_falls_back_to_secondary_command_when_bom_has_no_dependency_graph(self) -> None:
        instance = self._make_instance()
        document = MagicMock(spec=Document)
        document.content = 'some content'

        bom_doc = MagicMock(spec=Document)
        bom_doc.content = json.dumps({'dependencies': []})
        fallback_doc = MagicMock(spec=Document)
        fallback_doc.content = '[INFO] com.example:root:jar:1.0\n+- io.netty:netty-all:jar:4.1.0'

        with (
            patch.object(instance, 'get_manifest_file_path', return_value='/project/pom.xml'),
            patch(
                'cycode.cli.files_collector.sca.maven.restore_maven_dependencies.BaseRestoreDependencies.try_restore_dependencies',
                return_value=bom_doc,
            ),
            patch.object(instance, 'restore_from_secondary_command', return_value=fallback_doc) as mock_fallback,
        ):
            result = instance.try_restore_dependencies(document)

        mock_fallback.assert_called_once_with(document, '/project/pom.xml')
        assert result is fallback_doc

    def test_returns_bom_document_when_dependency_graph_is_present(self) -> None:
        instance = self._make_instance()
        document = MagicMock(spec=Document)
        document.content = 'some content'

        bom_doc = MagicMock(spec=Document)
        bom_doc.content = json.dumps(
            {
                'dependencies': [
                    {'ref': 'pkg:maven/com.example/root@1.0', 'dependsOn': ['pkg:maven/io.netty/netty@4.1.0']}
                ]
            }
        )

        with (
            patch.object(instance, 'get_manifest_file_path', return_value='/project/pom.xml'),
            patch(
                'cycode.cli.files_collector.sca.maven.restore_maven_dependencies.BaseRestoreDependencies.try_restore_dependencies',
                return_value=bom_doc,
            ),
            patch.object(instance, 'restore_from_secondary_command') as mock_fallback,
        ):
            result = instance.try_restore_dependencies(document)

        mock_fallback.assert_not_called()
        assert result is bom_doc

    def test_uses_plugin_version_2_9_1(self) -> None:
        instance = self._make_instance()
        commands = instance.get_commands('/path/to/pom.xml')
        assert len(commands) == 1
        assert 'org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom' in commands[0]
