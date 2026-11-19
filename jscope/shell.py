"""Interactive investigation shell (`jscope` with no arguments in a terminal).

A thin loop over the direct CLI: every line is parsed by the same argparse tree and runs the same command
functions, with the investigation context (jscope.session) supplying target, scope and findings. There are no
menus and no modes. Three conveniences only:

  <url-or-path>   starts/refreshes an investigation (same as `jscope <target>`)
  <number>        shows that ranked finding (same as `show N`)
  confirm/verify  show what would be sent, then ask once before any request leaves the machine
"""
from __future__ import annotations

import contextlib
import io
import shlex
import sys
from pathlib import Path
from typing import Callable

from jscope.session import Session, is_url_like

HELP = """\
  <url-or-path>        analyze a target (starts the investigation)
  findings [text]      ranked findings        --category X --min-confidence HIGH --unverified --all
  show <n|id>          one finding: evidence, route context, next actions   (just typing <n> works)
  graph                route -> component -> API -> guard map     --unprotected --filter text
  confirm              check that endpoint findings respond (read-only; asks before sending)
  verify [n]           try to reproduce a finding (active test; asks before sending)
  report [--format F]  markdown | html | json | sarif | human
  status               target, scope, evidence state
  use <target>         switch target without analyzing
  <any jscope command> works too (e.g. doctor, ws-scan, observe); help <command> for its options
  exit
"""


def _prompt(sess: Session) -> str:
    return f"jscope[{sess.label()}]> " if sess.active else "jscope> "


def _dispatch(argv: list[str], main: Callable) -> int:
    try:
        return main(argv)
    except SystemExit as exc:                       # argparse errors / --help must not kill the shell
        return exc.code if isinstance(exc.code, int) else 0
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


def _ask_yes(question: str, ask: Callable[[str], str]) -> bool:
    try:
        return ask(f"{question} [y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _gated_runtime(verb: str, rest: list[str], main: Callable, ask: Callable[[str], str]) -> int:
    """The one place the shell asks a question: before runtime traffic. Everything else just runs."""
    sess = Session.load()
    if "--authorize-active-tests" in rest:
        return _dispatch([verb, *rest], main)          # user already authorized explicitly on the command line
    if verb == "confirm":
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = _dispatch(["confirm", "--dry-run", *rest], main)
        plan = buf.getvalue()
        print(plan, end="")
        sends = sum(1 for line in plan.splitlines() if line.strip().startswith("SEND"))
        if rc != 0 or sends == 0:
            return rc
        what = f"Send {sends} read-only request(s) to {sess.host or 'the target'}?"
    else:
        what = (f"Run active verification against {sess.host or 'the target'}? "
                "This sends test requests (including cross-identity comparisons if identities are supplied).")
    if not _ask_yes(what, ask):
        print("not sent")
        return 0
    return _dispatch([verb, "--authorize-active-tests", *rest], main)


def handle_line(line: str, main: Callable, ask: Callable[[str], str]) -> int | None:
    """Run one shell line. Returns None to leave the shell, else the command's exit status."""
    line = line.strip()
    if not line:
        return 0
    if line.lower() in ("exit", "quit", "q"):
        return None
    try:
        argv = shlex.split(line)
    except ValueError as exc:
        print(f"could not parse: {exc}", file=sys.stderr)
        return 1
    if argv[0] == "jscope":
        argv = argv[1:]
        if not argv:
            return 0
    head = argv[0]
    if head in ("help", "?"):
        if len(argv) > 1:
            return _dispatch([argv[1], "--help"], main)
        print(HELP, end="")
        return 0
    if head.lstrip("#").isdigit():
        return _dispatch(["show", *argv], main)
    if head in ("confirm", "verify"):
        return _gated_runtime(head, argv[1:], main, ask)
    from jscope.cli import KNOWN_COMMANDS
    if head not in KNOWN_COMMANDS and not head.startswith("-") and (Path(head).exists() or is_url_like(head)):
        return _dispatch(["go", *argv], main)
    return _dispatch(argv, main)


def run_shell(ask: Callable[[str], str] | None = None) -> int:
    from jscope.cli import main
    sess = Session.load()
    if sess.active:
        print(f"resuming {sess.target}   (type 'status', or 'help')")
    else:
        print("JScope. Type a URL or path to start, or 'help'.")
    try:
        import readline  # noqa: F401  (line editing/history where available)
    except ImportError:
        pass
    read = ask or input
    while True:
        try:
            line = read(_prompt(Session.load()))
        except EOFError:
            print()
            return 0
        except KeyboardInterrupt:
            print()
            continue
        status = handle_line(line, main, read)
        if status is None:
            return 0
