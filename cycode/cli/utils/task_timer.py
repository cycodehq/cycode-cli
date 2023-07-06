from _thread import interrupt_main
from threading import Event, Thread
from types import TracebackType
from typing import Callable, Dict, List, Optional, Type


class FunctionContext:
    def __init__(self, function: Callable, args: Optional[List] = None, kwargs: Optional[Dict] = None) -> None:
        self.function = function
        self.args = args or []
        self.kwargs = kwargs or {}


class TimerThread(Thread):
    """
    Custom thread class for executing timer in the background

    Members:
        timeout - the amount of time to count until timeout in seconds
        quit_function (Mandatory) - function to perform when reaching to timeout
    """

    def __init__(self, timeout: int, quit_function: FunctionContext) -> None:
        Thread.__init__(self)
        self._timeout = timeout
        self._quit_function = quit_function
        self.event = Event()

    def run(self) -> None:
        self._run_quit_function_on_timeout()

    def stop(self) -> None:
        self.event.set()

    def _run_quit_function_on_timeout(self) -> None:
        self.event.wait(self._timeout)
        if not self.event.is_set():
            self._call_quit_function()
        self.stop()

    def _call_quit_function(self) -> None:
        self._quit_function.function(*self._quit_function.args, **self._quit_function.kwargs)


class TimeoutAfter:
    """
    A task wrapper for controlling how much time a task should be run before timing out

    Use Example:
        with TimeoutAfter(5, repeat_function=FunctionContext(x), repeat_interval=2):
            <task logic>

    Members:
        timeout - the amount of time to count until timeout in seconds
        quit_function (Optional) - function to perform when reaching to timeout,
                                   the default option is to interrupt main thread
    """

    def __init__(self, timeout: int, quit_function: Optional[FunctionContext] = None) -> None:
        self.timeout = timeout
        self._quit_function = quit_function or FunctionContext(function=self.timeout_function)
        self.timer = TimerThread(timeout, quit_function=self._quit_function)

    def __enter__(self) -> None:
        if self.timeout:
            self.timer.start()

    def __exit__(
        self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> None:
        if self.timeout:
            self.timer.stop()

        # catch the exception of interrupt_main before exiting
        # the with statement and throw timeout error instead
        if exc_type == KeyboardInterrupt:
            raise TimeoutError(f'Task timed out after {self.timeout} seconds')

    def timeout_function(self) -> None:
        interrupt_main()
