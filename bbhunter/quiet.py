#!/usr/bin/env python3
"""Stop asyncio printing DNS failures over the top of the interface.

Resolving thousands of names that do not exist is normal work for this
framework: permutation brute-forcing exists precisely to try names that mostly
will not resolve. When one of those lookups fails inside a connection attempt
that has already been abandoned — a timeout fired, a happy-eyeballs race was
already won, a stage was cancelled — asyncio finds an exception on a future
nobody awaited and prints

    Future exception was never retrieved
    future: <Future finished exception=gaierror(-2, 'Name or service not known')>

to stderr. Nothing is wrong: the lookup failed, the caller had already moved
on. But it scrolls the terminal you are reading the run from.

This installs a loop exception handler that counts those, reports the count
once rather than each occurrence, and passes everything else to the handler
that was already there. It deliberately swallows nothing else: a bug that
raises anything other than a name-resolution failure is still printed in full.
"""

from __future__ import annotations

import socket

#: Name resolution failures, by errno. -2 EAI_NONAME, -3 EAI_AGAIN,
#: -5 EAI_NODATA, -8 EAI_SERVICE, 11001 on Windows.
_DNS_ERRNOS = {-2, -3, -5, -8, 11001}
_FIRST_REPORT_AT = 1
_THEN_EVERY = 500


class _Counter:
    def __init__(self):
        self.total = 0


def _is_name_failure(exc):
    if isinstance(exc, socket.gaierror):
        return True
    if isinstance(exc, OSError) and exc.errno in _DNS_ERRNOS:
        return True
    return False


def install(loop, say=None):
    """Quieten abandoned name-resolution failures on this loop.

    `say(text)` is called at most a handful of times, so the fact that lookups
    are failing is still visible — just not once per name.
    """
    previous = loop.get_exception_handler()
    counter = _Counter()

    def handler(the_loop, context):
        exc = context.get("exception")
        message = context.get("message", "")
        if exc is not None and _is_name_failure(exc) and "never retrieved" in message:
            counter.total += 1
            if say and (counter.total == _FIRST_REPORT_AT
                        or counter.total % _THEN_EVERY == 0):
                say(f"{counter.total} name lookup(s) failed after the caller "
                    f"had moved on (a name that does not resolve). This is "
                    f"normal during permutation brute-forcing and is counted, "
                    f"not printed.")
            return
        if previous is not None:
            previous(the_loop, context)
        else:
            the_loop.default_exception_handler(context)

    loop.set_exception_handler(handler)
    return counter
