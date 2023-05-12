import yaml
from typing import Dict


def read_file(filename: str) -> Dict:
    with open(filename, 'r', encoding="utf-8") as file:
        return yaml.safe_load(file)


def update_file(filename: str, content: Dict):
    try:
        with open(filename, 'r', encoding="utf-8") as file:
            file_content = yaml.safe_load(file)
    except FileNotFoundError:
        file_content = {}

    with open(filename, 'w', encoding="utf-8") as file:
        file_content = _deep_update(file_content, content)
        yaml.safe_dump(file_content, file)


def _deep_update(source, overrides):
    for key, value in overrides.items():
        if isinstance(value, dict) and value:
            source[key] = _deep_update(source.get(key, {}), value)
        else:
            source[key] = overrides[key]
    return source
