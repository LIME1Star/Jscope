"""JScope's terminal presentation layer.

Presentation only: analysis, findings, and report generation remain independent.
Animations are restricted to interactive terminals; redirected output stays plain.
"""
from __future__ import annotations

import itertools
import os
import sys
import threading
import time
from contextlib import contextmanager


class _Style:
    RESET = "\x1b[0m"
    DIM = "\x1b[2m"
    BOLD = "\x1b[1m"
    WHITE = "\x1b[97m"
    SILVER = "\x1b[37m"
    LIME = "\x1b[38;5;154m"
    AMBER = "\x1b[38;5;214m"
    RED = "\x1b[38;5;203m"


def _color_enabled(stream) -> bool:
    return bool(getattr(stream, "isatty", lambda: False)()) and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"


def _paint(value: str, code: str, enabled: bool) -> str:
    return f"{code}{value}{_Style.RESET}" if enabled else value


def feather() -> str:
    """Small ASCII-native signature: reliable across terminal fonts and encodings."""
    enabled = _color_enabled(sys.stderr)
    return _paint("//>", _Style.LIME + _Style.BOLD, enabled)


def banner() -> None:
    """Print the compact White Hawk identity; never pollute machine-readable stdout."""
    enabled = _color_enabled(sys.stderr)
    mark = _paint("//>", _Style.LIME + _Style.BOLD, enabled)
    name = _paint("JSCOPE", _Style.WHITE + _Style.BOLD, enabled)
    tagline = _paint("JavaScript Intelligence", _Style.DIM, enabled)
    print(f"\n  {mark}  {name}  {tagline}", file=sys.stderr)


@contextmanager
def activity(label: str, *, announce: bool = True):
    """Show a quiet live indicator on TTYs, and deterministic status on other streams."""
    stream = sys.stderr
    tty = _color_enabled(stream)
    if announce and not tty:
        print(f"[>] {label}...", file=stream)
        try:
            yield
        except BaseException:
            print(f"[x] {label} failed", file=stream)
            raise
        else:
            print(f"[+] {label} complete", file=stream)
        return

    if not tty:
        yield
        return

    frames = itertools.cycle(("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"))
    stopped = threading.Event()
    def animate() -> None:
        while not stopped.is_set():
            frame = next(frames)
            line = f"\r  {_paint(frame, _Style.LIME, True)}  {_paint(label, _Style.SILVER, True)}"
            stream.write(line)
            stream.flush()
            stopped.wait(0.085)
    thread = threading.Thread(target=animate, daemon=True)
    if announce:
        thread.start()
    failed = False
    try:
        yield
    except BaseException:
        failed = True
        raise
    finally:
        if announce:
            stopped.set()
            thread.join(timeout=0.3)
            stream.write("\r\x1b[2K")
            marker = _paint('x' if failed else '+', (_Style.RED if failed else _Style.LIME) + _Style.BOLD, True)
            suffix = "failed" if failed else "complete"
            stream.write(f"  {marker}  {_paint(label, _Style.SILVER, True)} {_paint(suffix, _Style.DIM, True)}\n")
            stream.flush()
