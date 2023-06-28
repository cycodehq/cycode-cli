from cycode.cli.utils.string_utils import shortcut_dependency_paths


def test_shortcut_dependency_paths_single_dependencies():
    dependency_paths = "A"
    assert shortcut_dependency_paths(dependency_paths) == dependency_paths


def test_shortcut_dependency_paths_two_dependencies():
    dependency_paths = "A -> B"
    assert shortcut_dependency_paths(dependency_paths) == dependency_paths


def test_shortcut_dependency_paths_three_dependencies():
    dependency_paths = "A -> B -> C"
    expected_result = "A -> ... -> C"
    assert shortcut_dependency_paths(dependency_paths) == expected_result
