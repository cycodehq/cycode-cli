__version__ = '0.0.0'  # DON'T TOUCH. Placeholder. Will be filled automatically on poetry build from Git Tag

if __version__ == '0.0.1.dev1':
    # If CLI was installed from shallow clone, __version__ will be 0.0.1.dev1 due to non-strict versioning.
    # This happens when installing CLI as pre-commit hook.
    # We are not able to provide the version based on Git Tag in this case.
    # This fallback version is maintained manually.

    # One benefit of it is that we could pass the version with a special suffix to mark pre-commit hook usage.

    import os
    version_filepath = os.path.join(os.path.dirname(__file__), 'pre-commit-hook-version')
    with open(version_filepath, 'r', encoding='UTF-8') as f:
        __version__ = f.read().strip()
