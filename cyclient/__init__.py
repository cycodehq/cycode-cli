"""Cycode Client"""
from .config import logger
from version import version

__version__ = version

__all__ = [
    "logger",
    "__version__"
]
