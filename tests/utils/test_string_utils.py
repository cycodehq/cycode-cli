from cycode.cli.utils.string_utils import shortcut_dependency_paths


def test_shortcut_dependency_paths_list_single_dependencies() -> None:
    dependency_paths = 'A, A -> B, A -> B -> C'
    expected_result = 'A\nA -> B\nA -> ... -> C'
    assert shortcut_dependency_paths(dependency_paths) == expected_result
