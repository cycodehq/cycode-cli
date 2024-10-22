![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/cycodehq/cycode-cli/tests.yml)
![PyPI - Version](https://img.shields.io/pypi/v/cycode)
![GitHub License](https://img.shields.io/github/license/cycodehq/cycode-cli)

## How to contribute to Cycode CLI

The minimum version of Python that we support is 3.8.
We recommend using this version for local development.
But it’s fine to use a higher version without using new features from these versions.

The project is under Poetry project management.
To deal with it, you should install it on your system:

Install Poetry (feel free to use Brew, etc):

```shell
curl -sSL https://install.python-poetry.org | python - -y
```

Add Poetry to PATH if required.

Add a plugin to support dynamic versioning from Git Tags:

```shell
poetry self add "poetry-dynamic-versioning[plugin]"
```

Install dependencies of the project:

```shell
poetry install
```

Check that the version is valid (not 0.0.0):

```shell
poetry version
```

You are ready to write code!

To run the project use:

```shell
poetry run cycode
```

or main entry point in an activated virtual environment:

```shell
python cycode/cli/main.py
```

### Code linting and formatting

We use `ruff`.
It is configured well, so you don’t need to do anything.
You can see all enabled rules in the `pyproject.toml` file.
Both tests and the main codebase are checked.
Try to avoid type annotations like `Any`, etc.

GitHub Actions will check that your code is formatted well. You can run it locally:

```shell
# lint
poetry run ruff check .
# format
poetry run ruff format .
```

Many rules support auto-fixing. You can run it with the `--fix` flag.

### Branching and versioning

We use the `main` branch as the main one.
All development should be done in feature branches.
When you are ready create a Pull Request to the `main` branch.

Each commit in the `main` branch will be built and published to PyPI as a pre-release!
Such builds could be installed with the `--pre` flag. For example:

```shell
pip install --pre cycode
```

Also, you can select a specific version of the pre-release:

```shell
pip install cycode==1.7.2.dev6
```

We are using [Semantic Versioning](https://semver.org/) and the version is generated automatically from Git Tags. So,
when you are ready to release a new version, you should create a new Git Tag. The version will be generated from it.

Pre-release versions are generated on distance from the latest Git Tag. For example, if the latest Git Tag is `1.7.2`,
then the next pre-release version will be `1.7.2.dev1`.

We are using GitHub Releases to create Git Tags with changelogs.
For changelogs, we are using a standard template
of [Automatically generated release notes](https://docs.github.com/en/repositories/releasing-projects-on-github/automatically-generated-release-notes).

### Testing

We are using `pytest` for testing. You can run tests with:

```shell
poetry run pytest
```

The library used for sending requests is [requests](https://github.com/psf/requests).
To mock requests, we are using the [responses](https://github.com/getsentry/responses) library.
All requests must be mocked.

To see the code coverage of the project, you can run:

```shell
poetry run coverage run -m pytest .
```

To generate the HTML report, you can run:

```shell
poetry run coverage html
```

The report will be generated in the `htmlcov` folder.

### Documentation

Keep [README.md](README.md) up to date.
All CLI commands are documented automatically if you add a docstring to the command.
Clean up the changelog before release.

### Publishing

New versions are published automatically on the new GitHub Release.
It uses the OpenID Connect publishing mechanism to upload on PyPI.

[Homebrew formula](https://formulae.brew.sh/formula/cycode) is updated automatically on the new PyPI release.

The CLI is also distributed as executable files for Linux, macOS, and Windows.
It is powered by [PyInstaller](https://pyinstaller.org/) and the process is automated by GitHub Actions.
These executables are attached to GitHub Releases as assets.

To pack the project locally, you should run:

```shell
poetry build
```

It will create a `dist` folder with the package (sdist and wheel). You can install it locally:

```shell
pip install dist/cycode-{version}-py3-none-any.whl
```

To create an executable file locally, you should run:

```shell
poetry run pyinstaller pyinstaller.spec
```

It will create an executable file for **the current platform** in the `dist` folder.
