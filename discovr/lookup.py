"""Bounded DNS work that cannot keep the portable application alive on exit.

System DNS calls cannot be interrupted. A fixed daemon pool limits the number of
stalled OS calls, while callers have their own deadline and can keep partial results.
"""
import asyncio
import queue
import threading
from concurrent.futures import Future

_queue = queue.Queue(maxsize=128)
_lock = threading.Lock()
_started = False


def _worker():
    while True:
        future, fn, value = _queue.get()
        try:
            if future.set_running_or_notify_cancel():
                try:
                    future.set_result(fn(value))
                except Exception as exc:
                    future.set_exception(exc)
        finally:
            _queue.task_done()


def _submit(fn, value):
    global _started
    with _lock:
        if not _started:
            for i in range(16):
                threading.Thread(target=_worker, daemon=True, name=f"discovr-dns-{i}").start()
            _started = True
    future = Future()
    try:
        _queue.put_nowait((future, fn, value))
    except queue.Full:
        future.cancel()
    return future


async def lookup_many(values, fn, fallback, cancel=None, timeout=3):
    """Return results in input order; cap queued work and give each lookup a deadline."""
    values = list(values)
    results = [fallback] * len(values)
    work = iter(enumerate(values))

    async def worker():
        for index, value in work:
            if cancel is not None and cancel.is_set():
                return
            future = _submit(fn, value)
            if future.cancelled():
                continue
            try:
                results[index] = await asyncio.wait_for(asyncio.wrap_future(future), timeout)
            except (Exception, asyncio.CancelledError):
                # Failed/slow DNS is missing context, not evidence the asset is absent.
                future.cancel()

    await asyncio.gather(*(worker() for _ in range(min(32, len(values)))))
    return results
