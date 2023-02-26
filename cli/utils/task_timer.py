from threading import Thread, Event
from _thread import interrupt_main
from typing import Optional, Callable, List, Dict, Type
from types import TracebackType


class FunctionContext:
    FUNCTION: Callable
    ARGS: Optional[List]
    KWARGS: Optional[Dict]

    def __init__(self, function: Callable, args: Optional[List] = None, kwargs: Optional[Dict] = None):
        self.FUNCTION = function
        self.ARGS = args or []
        self.KWARGS = kwargs or {}


class TimerThread(Thread):

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
        # do not perform any action till timeout
        if not self._repeat_function or not self._repeat_interval:
            self._run_quit_function_on_timeout()
            return

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
            self._call_repeat_till_quit_function()
            self._timeout -= self._repeat_interval
            if self._timeout <= 0:
                break

        if not self.event.is_set():
            self._call_quit_function()
        self.stop()

    def _call_quit_function(self):
        self._quit_function.FUNCTION(*self._quit_function.ARGS, **self._quit_function.KWARGS)

    def _call_repeat_till_quit_function(self):
        self._repeat_function.FUNCTION(*self._repeat_function.ARGS, **self._repeat_function.KWARGS)


class TimeoutAfter:

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
        if exc_type == KeyboardInterrupt:
            raise TimeoutError()

    def timeout_function(self):
        interrupt_main()
