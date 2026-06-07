import time as _time

# Unix-epoch wall clock captured at the earliest possible moment of CLI
# startup. Sent as `scan_parameters.cli_start_time` so the server can compute
# end-to-end scan duration from the moment the user actually triggered it.
_BOOT_WALL: float = _time.time()

__version__ = '0.0.0'  # DON'T TOUCH. Placeholder. Will be filled automatically on poetry build from Git Tag
