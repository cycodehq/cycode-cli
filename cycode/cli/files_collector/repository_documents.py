from collections.abc import Iterator
from typing import TYPE_CHECKING, Optional, Union

from cycode.cli.utils.git_proxy import git_proxy

if TYPE_CHECKING:
    from git import Blob, Repo
    from git.objects.base import IndexObjUnion
    from git.objects.tree import TraversedTreeTup


def _should_process_git_object(obj: 'Blob', _: int) -> bool:
    return obj.type == 'blob' and obj.size > 0


def get_git_repository_tree_file_entries(
    path: str, branch: str
) -> Union[Iterator['IndexObjUnion'], Iterator['TraversedTreeTup']]:
    return git_proxy.get_repo(path).tree(branch).traverse(predicate=_should_process_git_object)


def get_file_content_from_commit_path(repo: 'Repo', commit: str, file_path: str) -> Optional[str]:
    try:
        return repo.git.show(f'{commit}:{file_path}')
    except git_proxy.get_git_command_error():
        return None
