from cycode.cli import consts


def is_git_diff_based_scan(scan_type: str, command_scan_type: str) -> bool:
    return (
        command_scan_type in consts.COMMIT_RANGE_BASED_COMMAND_SCAN_TYPES
        and scan_type in consts.COMMIT_RANGE_SCAN_SUPPORTED_SCAN_TYPES
    )
