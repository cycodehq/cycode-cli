import os
import click


def github_action_range():
    before_sha = os.getenv("BEFORE_SHA")
    push_base_sha = os.getenv("BASE_SHA")
    pr_base_sha = os.getenv("PR_BASE_SHA")
    default_branch = os.getenv("DEFAULT_BRANCH")
    head_sha = os.getenv("GITHUB_SHA")
    ref = os.getenv("GITHUB_REF")

    click.echo(f"{before_sha}, {push_base_sha}, {pr_base_sha}, {default_branch}, {head_sha}, {ref}")
    if before_sha and before_sha != NO_COMMITS:
        return f"{before_sha}..."

    return "..."

    # if pr_base_sha and pr_base_sha != FIRST_COMMIT:
    #     return f"{pr_base_sha}..."
    #
    # if push_base_sha and push_base_sha != "null":
    #     return f"{push_base_sha}..."


def circleci_range():
    before_sha = os.getenv("BEFORE_SHA")
    current_sha = os.getenv("CURRENT_SHA")
    commit_range = f"{before_sha}...{current_sha}"
    click.echo(f"commit range: {commit_range}")

    if not commit_range.startswith('...'):
        return commit_range

    commit_sha = os.getenv("CIRCLE_SHA1", "HEAD")

    return f'{commit_sha}~1...'


def gitlab_range():
    before_sha = os.getenv("CI_COMMIT_BEFORE_SHA")
    commit_sha = os.getenv("CI_COMMIT_SHA", "HEAD")

    if before_sha and before_sha != NO_COMMITS:
        return f"{before_sha}..."

    return f"{commit_sha}"


def get_commit_range():
    if os.getenv("GITHUB_ACTIONS"):
        return github_action_range()
    elif os.getenv("CIRCLECI"):
        return circleci_range()
    elif os.getenv("GITLAB_CI"):
        return gitlab_range()
    else:
        raise click.ClickException("CI framework is not supported")


NO_COMMITS = "0000000000000000000000000000000000000000"
