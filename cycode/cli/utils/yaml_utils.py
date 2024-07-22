from typing import Any, Dict, Hashable, TextIO

import yaml


def _yaml_safe_load(file: TextIO) -> Dict[Hashable, Any]:
    # loader.get_single_data could return None
    loaded_file = yaml.safe_load(file)
    if loaded_file is None:
        return {}

    return loaded_file


def read_file(filename: str) -> Dict[Hashable, Any]:
    with open(filename, 'r', encoding='UTF-8') as file:
        return _yaml_safe_load(file)


def write_file(filename: str, content: Dict[Hashable, Any]) -> None:
    with open(filename, 'w', encoding='UTF-8') as file:
        yaml.safe_dump(content, file)


def update_file(filename: str, content: Dict[Hashable, Any]) -> None:
    try:
        file_content = read_file(filename)
    except FileNotFoundError:
        file_content = {}

    write_file(filename, _deep_update(file_content, content))


def _deep_update(source: Dict[Hashable, Any], overrides: Dict[Hashable, Any]) -> Dict[Hashable, Any]:
    for key, value in overrides.items():
        if isinstance(value, dict) and value:
            source[key] = _deep_update(source.get(key, {}), value)
        else:
            source[key] = overrides[key]

    return source
