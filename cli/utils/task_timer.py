from threading import Thread, Event
from _thread import interrupt_main
from typing import Optional, Callable, List, Dict, Type
from types import TracebackType


class FunctionContext:

    def __init__(self, function: Callable, args: List = None, kwargs: Dict = None):
        self.function = function
        self.args = args or []
        self.kwargs = kwargs or {}


class TimerThread(Thread):
    """
    Custom thread class for executing timer in the background, in addition giving the ability to perform
    action every X seconds until reaching to the configured timeout

    Members:
        timeout - the amount of time to count until timeout in seconds
        quit_function (Mandatory) - function to perform when reaching to timeout
        repeat_function (Optional) - function to perform every X seconds until reaching to timeout
        repeat_interval (Optional) - the period to wait until performing repeat function again in seconds
    """
    def __init__(self, timeout: int,
                 quit_function: FunctionContext,
                 repeat_function: Optional[FunctionContext] = None,
                 repeat_interval: Optional[int] = None):
        Thread.__init__(self)
        self._timeout = timeout
        self._quit_function = quit_function
        self._repeat_function = repeat_function
        self._repeat_interval = repeat_interval
        self.event = Event()

    def run(self):
        # do not perform any functionality till timeout, perform quit function on timeout
        if not self._repeat_function or not self._repeat_interval:
            self._run_quit_function_on_timeout()
            return

        # perform repeat function every X time according to repeat interval
        # until reaching to timeout, then if timeout perform quit function
        self._run_repeat_function_until_timeout_and_quit_function_on_timeout()

    def stop(self):
        self.event.set()

    def _run_quit_function_on_timeout(self):
        self.event.wait(self._timeout)
        if not self.event.is_set():
            self._call_quit_function()
        self.stop()

    def _run_repeat_function_until_timeout_and_quit_function_on_timeout(self):
        while not self.event.wait(self._repeat_interval):
            self._call_repeat_function()
            self._timeout -= self._repeat_interval
            if self._timeout <= 0:
                break

        if not self.event.is_set():
            self._call_quit_function()
        self.stop()

    def _call_quit_function(self):
        self._quit_function.function(*self._quit_function.args, **self._quit_function.kwargs)

    def _call_repeat_function(self):
        self._repeat_function.function(*self._repeat_function.args, **self._repeat_function.kwargs)


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
        repeat_function (Optional) - function to perform every X seconds until reaching to timeout
        repeat_interval (Optional) - the period to wait until performing repeat function again in seconds
    """
    def __init__(self, timeout: int,
                 quit_function: Optional[FunctionContext] = None,
                 repeat_function: Optional[FunctionContext] = None,
                 repeat_interval: Optional[int] = None):
        self.timeout = timeout
        self._quit_function = quit_function or FunctionContext(function=self.timeout_function)
        self._repeat_function = repeat_function
        self._repeat_interval = repeat_interval
        self.timer = TimerThread(timeout, quit_function=self._quit_function, repeat_function=self._repeat_function,
                                 repeat_interval=repeat_interval)

    def __enter__(self) -> None:
        if self.timeout:
            self.timer.start()

    def __exit__(self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException],
                 exc_tb: Optional[TracebackType]) -> None:
        if self.timeout:
            self.timer.stop()

        # catch the exception of interrupt_main before exiting
        # the with statement and throw timeout error instead
        if exc_type == KeyboardInterrupt:
            raise TimeoutError(f"Task timed out after {self.timeout} seconds")

    def timeout_function(self):
        interrupt_main()
