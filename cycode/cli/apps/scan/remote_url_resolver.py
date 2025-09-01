from typing import Optional

from cycode.cli import consts
from cycode.cli.utils.git_proxy import git_proxy
from cycode.cli.utils.shell_executor import shell
from cycode.logger import get_logger

logger = get_logger('Remote URL Resolver')


def _get_plastic_repository_name(path: str) -> Optional[str]:
    """Get the name of the Plastic repository from the current working directory.

    The command to execute is:
        cm status --header --machinereadable --fieldseparator=":::"

    Example of status header in machine-readable format:
        STATUS:::0:::Project/RepoName:::OrgName@ServerInfo
    """
    try:
        command = [
            'cm',
            'status',
            '--header',
            '--machinereadable',
            f'--fieldseparator={consts.PLASTIC_VCS_DATA_SEPARATOR}',
        ]

        status = shell(
            command=command, timeout=consts.PLASTIC_VSC_CLI_TIMEOUT, working_directory=path, silent_exc_info=True
        )
        if not status:
            logger.debug('Failed to get Plastic repository name (command failed)')
            return None

        status_parts = status.split(consts.PLASTIC_VCS_DATA_SEPARATOR)
        if len(status_parts) < 2:
            logger.debug('Failed to parse Plastic repository name (command returned unexpected format)')
            return None

        return status_parts[2].strip()
    except Exception:
        logger.debug('Failed to get Plastic repository name. Probably not a Plastic repository')
        return None


def _get_plastic_repository_list(working_dir: Optional[str] = None) -> dict[str, str]:
    """Get the list of Plastic repositories and their GUIDs.

    The command to execute is:
        cm repo list --format="{repname}:::{repguid}"

    Example line with data:
        Project/RepoName:::tapo1zqt-wn99-4752-h61m-7d9k79d40r4v

    Each line represents an individual repository.
    """
    repo_name_to_guid = {}

    try:
        command = ['cm', 'repo', 'ls', f'--format={{repname}}{consts.PLASTIC_VCS_DATA_SEPARATOR}{{repguid}}']

        status = shell(
            command=command, timeout=consts.PLASTIC_VSC_CLI_TIMEOUT, working_directory=working_dir, silent_exc_info=True
        )
        if not status:
            logger.debug('Failed to get Plastic repository list (command failed)')
            return repo_name_to_guid

        status_lines = status.splitlines()
        for line in status_lines:
            data_parts = line.split(consts.PLASTIC_VCS_DATA_SEPARATOR)
            if len(data_parts) < 2:
                logger.debug('Failed to parse Plastic repository list line (unexpected format), %s', {'line': line})
                continue

            repo_name, repo_guid = data_parts
            repo_name_to_guid[repo_name.strip()] = repo_guid.strip()

        return repo_name_to_guid
    except Exception as e:
        logger.debug('Failed to get Plastic repository list', exc_info=e)
        return repo_name_to_guid


def _try_to_get_plastic_remote_url(path: str) -> Optional[str]:
    repository_name = _get_plastic_repository_name(path)
    if not repository_name:
        return None

    repository_map = _get_plastic_repository_list(path)
    if repository_name not in repository_map:
        logger.debug('Failed to get Plastic repository GUID (repository not found in the list)')
        return None

    repository_guid = repository_map[repository_name]
    return f'{consts.PLASTIC_VCS_REMOTE_URI_PREFIX}{repository_guid}'


def _try_get_git_remote_url(path: str) -> Optional[str]:
    try:
        repo = git_proxy.get_repo(path, search_parent_directories=True)
        remote_url = repo.remotes[0].config_reader.get('url')
        logger.debug('Found Git remote URL, %s', {'remote_url': remote_url, 'repo_path': repo.working_dir})
        return remote_url
    except Exception as e:
        logger.debug('Failed to get Git remote URL. Probably not a Git repository', exc_info=e)
        return None


def _try_get_any_remote_url(path: str) -> Optional[str]:
    remote_url = _try_get_git_remote_url(path)
    if not remote_url:
        remote_url = _try_to_get_plastic_remote_url(path)

    return remote_url


def get_remote_url_scan_parameter(paths: tuple[str, ...]) -> Optional[str]:
    remote_urls = set()
    for path in paths:
        # FIXME(MarshalX): perf issue. This looping will produce:
        #  - len(paths) Git subprocess calls in the worst case
        #  - len(paths)*2 Plastic SCM subprocess calls
        remote_url = _try_get_any_remote_url(path)
        if remote_url:
            remote_urls.add(remote_url)

    if len(remote_urls) == 1:
        # we are resolving remote_url only if all paths belong to the same repo (identical remote URLs),
        # otherwise, the behavior is undefined
        remote_url = remote_urls.pop()

        logger.debug(
            'Single remote URL found. Scan will be associated with organization, %s', {'remote_url': remote_url}
        )
        return remote_url

    logger.debug(
        'Multiple different remote URLs found. Scan will not be associated with organization, %s',
        {'remote_urls': remote_urls},
    )

    return None
