"""Shared helpers for VS Code and its forks, such as Cursor: where they keep their data, and reading their databases."""

import platform
import sqlite3
from contextlib import closing
from pathlib import Path


def vscode_user_data_dir(product_name: str = 'Code') -> Path:
    """Per-platform user data directory of VS Code or a fork: 'Code', 'Code - Insiders' or 'Cursor'."""
    if platform.system() == 'Darwin':
        return Path.home() / 'Library' / 'Application Support' / product_name
    if platform.system() == 'Windows':
        return Path.home() / 'AppData' / 'Roaming' / product_name
    return Path.home() / '.config' / product_name


def read_only_query(db_path: Path, sql: str, params: tuple = ()) -> list[tuple]:
    """The rows of a query on an app's SQLite database, opened read-only: the app keeps writing to the file."""
    with closing(sqlite3.connect(f'{db_path.resolve().as_uri()}?mode=ro', uri=True, timeout=1)) as connection:
        return connection.execute(sql, params).fetchall()
