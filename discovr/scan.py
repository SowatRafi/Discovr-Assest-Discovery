"""Shared cooperative scan lifecycle; provider calls remain read-only.

Cancellation is checked between requests/pages. An in-flight SDK request is allowed
to finish within its timeout; no new work starts after the stop request.
"""
import logging
import threading

log = logging.getLogger(__name__)


class ScanCancelled(Exception):
    """Internal control flow; partial results have already been streamed to the caller."""


class ScanControl:
    def __init__(self, on_progress=None, on_asset=None, cancel=None):
        self.on_progress = on_progress or (lambda *args: None)
        self.on_asset = on_asset or (lambda asset: None)
        self.cancel = cancel
        self.warnings = []
        self.lock = threading.Lock()

    def check(self):
        if self.cancel is not None and self.cancel.is_set():
            raise ScanCancelled()

    def progress(self, done, total, stage):
        self.check()
        self.on_progress(done, total, stage)

    def emit(self, asset):
        self.check()
        self.on_asset(dict(asset))
        return asset

    def warn(self, message):
        with self.lock:
            self.warnings.append(message)
        log.warning("[!] %s", message)

    def pages(self, iterable):
        iterator = iter(iterable)
        while True:
            self.check()  # do not fetch another page after Stop
            try:
                page = next(iterator)
            except StopIteration:
                return
            self.check()
            yield page
