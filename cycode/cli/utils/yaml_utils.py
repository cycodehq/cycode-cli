from typing import Any, Dict, Hashable

import yaml


def read_file(filename: str) -> Dict[Hashable, Any]:
    with open(filename, 'r', encoding='UTF-8') as file:
        return yaml.safe_load(file)


def update_file(filename: str, content: Dict[Hashable, Any]) -> None:
    try:
        with open(filename, 'r', encoding='UTF-8') as file:
            file_content = yaml.safe_load(file)
    except FileNotFoundError:
        file_content = {}

    with open(filename, 'w', encoding='UTF-8') as file:
        file_content = _deep_update(file_content, content)
        yaml.safe_dump(file_content, file)


def _deep_update(source: Dict[Hashable, Any], overrides: Dict[Hashable, Any]) -> Dict[Hashable, Any]:
    for key, value in overrides.items():
        if isinstance(value, dict) and value:
            source[key] = _deep_update(source.get(key, {}), value)
        else:
            source[key] = overrides[key]
    return source
