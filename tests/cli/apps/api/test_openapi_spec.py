"""Tests for the OpenAPI spec parser."""

from cycode.cli.apps.api.openapi_spec import parse_spec_commands


def test_parse_spec_commands_groups_by_tag() -> None:
    spec = {
        'paths': {
            '/v4/projects': {
                'get': {'tags': ['Projects'], 'summary': 'Get projects'},
            },
            '/v4/violations': {
                'get': {'tags': ['Violations'], 'summary': 'Get violations'},
            },
        }
    }
    groups = parse_spec_commands(spec)
    assert set(groups.keys()) == {'Projects', 'Violations'}


def test_parse_spec_commands_extracts_path_params() -> None:
    spec = {
        'paths': {
            '/v4/projects/{projectId}': {
                'get': {
                    'tags': ['Projects'],
                    'parameters': [
                        {'name': 'projectId', 'in': 'path', 'required': True},
                        {'name': 'page_size', 'in': 'query', 'required': False},
                    ],
                },
            },
        }
    }
    groups = parse_spec_commands(spec)
    ep = groups['Projects'][0]
    assert len(ep['path_params']) == 1
    assert ep['path_params'][0]['name'] == 'projectId'
    assert len(ep['query_params']) == 1
    assert ep['query_params'][0]['name'] == 'page_size'


def test_parse_spec_commands_captures_deprecated_flag() -> None:
    spec = {
        'paths': {
            '/v4/old': {
                'get': {'tags': ['T'], 'summary': 'old', 'deprecated': True},
            },
            '/v4/new': {
                'get': {'tags': ['T'], 'summary': 'new'},
            },
        }
    }
    groups = parse_spec_commands(spec)
    by_path = {ep['path']: ep for ep in groups['T']}
    assert by_path['/v4/old']['deprecated'] is True
    assert by_path['/v4/new']['deprecated'] is False


def test_parse_spec_commands_no_tags_uses_other() -> None:
    spec = {
        'paths': {
            '/v4/foo': {'get': {}},
        }
    }
    groups = parse_spec_commands(spec)
    assert 'other' in groups


def test_parse_spec_commands_empty_spec() -> None:
    assert parse_spec_commands({}) == {}
    assert parse_spec_commands({'paths': {}}) == {}
