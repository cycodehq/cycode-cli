from cycode.cli import consts


def is_git_diff_based_scan(command_scan_type: str) -> bool:
    return command_scan_type in consts.COMMIT_RANGE_BASED_COMMAND_SCAN_TYPES
