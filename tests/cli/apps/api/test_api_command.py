"""Tests for the OpenAPI-to-Click translator."""

from cycode.cli.apps.api.api_command import (
    _find_common_prefix,
    _normalize_tag,
    _param_to_option_name,
    _path_to_command_name,
)

# --- _normalize_tag ---


def test_normalize_tag_simple() -> None:
    assert _normalize_tag('Projects') == 'projects'


def test_normalize_tag_multi_word() -> None:
    assert _normalize_tag('Scan Statistics') == 'scan-statistics'


def test_normalize_tag_with_special_chars() -> None:
    assert _normalize_tag('CLI scan statistics') == 'cli-scan-statistics'


def test_normalize_tag_strips_leading_trailing_separators() -> None:
    assert _normalize_tag('  Projects  ') == 'projects'


# --- _param_to_option_name ---


def test_param_to_option_name_snake_case() -> None:
    assert _param_to_option_name('page_size') == '--page-size'


def test_param_to_option_name_camel_case() -> None:
    assert _param_to_option_name('pageSize') == '--page-size'


def test_param_to_option_name_with_dot() -> None:
    assert _param_to_option_name('filter.status') == '--filter-status'


def test_param_to_option_name_already_kebab() -> None:
    assert _param_to_option_name('page-size') == '--page-size'


# --- _find_common_prefix ---


def test_find_common_prefix_empty() -> None:
    assert _find_common_prefix([]) == ''


def test_find_common_prefix_single_path() -> None:
    # Single path: use parent directory as prefix
    assert _find_common_prefix(['/v4/projects']) == '/v4'


def test_find_common_prefix_two_paths_with_common_parent() -> None:
    assert _find_common_prefix(['/v4/projects', '/v4/projects/assets']) == '/v4/projects'


def test_find_common_prefix_two_paths_with_grandparent() -> None:
    assert _find_common_prefix(['/v4/projects', '/v4/members']) == '/v4'


def test_find_common_prefix_identical_paths() -> None:
    assert _find_common_prefix(['/v4/projects', '/v4/projects']) == '/v4/projects'


# --- _path_to_command_name ---


def test_path_to_command_name_collection() -> None:
    # /v4/projects with prefix /v4/projects -> nothing left -> 'list'
    assert _path_to_command_name('/v4/projects', '/v4/projects', has_path_params=False) == 'list'


def test_path_to_command_name_single_resource() -> None:
    # /v4/projects/{id} with prefix /v4/projects -> only path param left -> 'view'
    assert _path_to_command_name('/v4/projects/{projectId}', '/v4/projects', has_path_params=True) == 'view'


def test_path_to_command_name_sub_resource() -> None:
    # /v4/projects/assets with prefix /v4/projects -> 'assets'
    assert _path_to_command_name('/v4/projects/assets', '/v4/projects', has_path_params=False) == 'assets'


def test_path_to_command_name_sub_resource_count() -> None:
    # /v4/violations/count with prefix /v4/violations -> 'count'
    assert _path_to_command_name('/v4/violations/count', '/v4/violations', has_path_params=False) == 'count'


def test_path_to_command_name_multi_segment() -> None:
    # /v4/projects/collisions/count with prefix /v4/projects -> 'collisions-count'
    assert (
        _path_to_command_name('/v4/projects/collisions/count', '/v4/projects', has_path_params=False)
        == 'collisions-count'
    )


def test_path_to_command_name_with_path_param_in_middle() -> None:
    # /v4/workflows/{id}/jobs with prefix /v4/workflows -> 'jobs' (path param stripped)
    assert _path_to_command_name('/v4/workflows/{workflowId}/jobs', '/v4/workflows', has_path_params=True) == 'jobs'


def test_path_to_command_name_kebab_case_normalization() -> None:
    # Path with underscores or special chars -> kebab-case
    assert _path_to_command_name('/v4/brokers/broker_metrics', '/v4/brokers', has_path_params=False) == 'broker-metrics'
