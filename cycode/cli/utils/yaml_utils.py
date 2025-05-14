import os
from collections.abc import Hashable
from typing import Any, TextIO

import yaml


def _deep_update(source: dict[Hashable, Any], overrides: dict[Hashable, Any]) -> dict[Hashable, Any]:
    for key, value in overrides.items():
        if isinstance(value, dict) and value:
            source[key] = _deep_update(source.get(key, {}), value)
        else:
            source[key] = overrides[key]

    return source


def _yaml_safe_load(file: TextIO) -> dict[Hashable, Any]:
    # loader.get_single_data could return None
    loaded_file = yaml.safe_load(file)
    if loaded_file is None:
        return {}

    return loaded_file


def read_yaml_file(filename: str) -> dict[Hashable, Any]:
    if not os.path.exists(filename):
        return {}

    with open(filename, encoding='UTF-8') as file:
        return _yaml_safe_load(file)


def write_yaml_file(filename: str, content: dict[Hashable, Any]) -> None:
    with open(filename, 'w', encoding='UTF-8') as file:
        yaml.safe_dump(content, file)


def update_yaml_file(filename: str, content: dict[Hashable, Any]) -> None:
    write_yaml_file(filename, _deep_update(read_yaml_file(filename), content))
