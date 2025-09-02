import os
from collections.abc import Hashable
from typing import Any, TextIO

import yaml

from cycode.logger import get_logger

logger = get_logger('YAML Utils')


def _deep_update(source: dict[Hashable, Any], overrides: dict[Hashable, Any]) -> dict[Hashable, Any]:
    for key, value in overrides.items():
        if isinstance(value, dict) and value:
            source[key] = _deep_update(source.get(key, {}), value)
        else:
            source[key] = overrides[key]

    return source


def _yaml_object_safe_load(file: TextIO) -> dict[Hashable, Any]:
    # loader.get_single_data could return None
    loaded_file = yaml.safe_load(file)

    if not isinstance(loaded_file, dict):
        # forbid literals at the top level
        logger.debug(
            'YAML file does not contain a dictionary at the top level: %s',
            {'filename': file.name, 'actual_type': type(loaded_file)},
        )
        return {}

    return loaded_file


def read_yaml_file(filename: str) -> dict[Hashable, Any]:
    if not os.access(filename, os.R_OK) or not os.path.exists(filename):
        logger.debug('Config file is not accessible or does not exist: %s', {'filename': filename})
        return {}

    with open(filename, encoding='UTF-8') as file:
        return _yaml_object_safe_load(file)


def write_yaml_file(filename: str, content: dict[Hashable, Any]) -> None:
    if not os.access(filename, os.W_OK) and os.path.exists(filename):
        logger.warning('No write permission for file. Cannot save config, %s', {'filename': filename})
        return

    with open(filename, 'w', encoding='UTF-8') as file:
        yaml.safe_dump(content, file)


def update_yaml_file(filename: str, content: dict[Hashable, Any]) -> None:
    write_yaml_file(filename, _deep_update(read_yaml_file(filename), content))
