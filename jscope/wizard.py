"""Guided interactive entry point for JScope.

The wizard is intentionally a thin presentation layer over the existing CLI
application services. It never invokes a shell and never broadens target scope.
"""
from __future__ import annotations

import shlex
from urllib.parse import urlparse


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"\n{prompt}{suffix}: ").strip()
    return value or (default or "")


def _choose(title: str, choices: list[str]) -> int:
    print(f"\n{title}")
    for i, choice in enumerate(choices, 1):
        print(f"  {i}. {choice}")
    while True:
        value = _ask("Select", "1")
        if value.isdigit() and 1 <= int(value) <= len(choices):
            return int(value)
        print(f"Enter a number from 1 to {len(choices)}.")


def launch_wizard() -> int:
    """Launch the interactive Auto / Manual workflow."""
    from jscope.cli import main

    print("\nWelcome to JScope.")
    while True:
        mode = _choose("Choose a mode", [
            "Auto mode — guided assessment",
            "Manual mode — run individual tools",
            "Exit",
        ])
        if mode == 3:
            print("JScope closed.")
            return 0
        if mode == 1:
            return _auto_mode(main)
        result = _manual_mode(main)
        if result is not None:
            return result


def _auto_mode(main) -> int:
    print("\nAUTO MODE")
    print("JScope will discover and analyze the target using its existing scope and transport controls.")
    target = _ask("Target URL or local project path")
    if not target:
        print("No target supplied. Returning to the mode selector.")
        return 0

    profile = _choose("Assessment profile", [
        "Passive discovery — skip well-known API specification probes",
        "Standard discovery — include well-known API specification paths",
    ])
    print("\nASSESSMENT REVIEW")
    print(f"  Target : {target}")
    parsed = urlparse(target if "://" in target else f"https://{target}")
    if parsed.hostname:
        print(f"  Scope  : exact target host ({parsed.hostname}); discovered requests remain host-bound")
    else:
        print("  Scope  : local filesystem path; no network requests")
    print(f"  Profile: {'Passive discovery' if profile == 1 else 'Standard discovery'}")
    print("  Actions: discover assets, download discovered resources, analyze local evidence, write report")
    print("  Limits : target-host transport policy; private/loopback destinations remain blocked by default")
    proceed = _ask("Start this assessment? (y/N)", "n").lower()
    if proceed not in {"y", "yes"}:
        print("Assessment cancelled.")
        return 0

    args = ["go", target, "--yes"]
    if profile == 1:
        args.append("--no-probe")
    return main(args, _show_banner=False)


def _manual_mode(main) -> int | None:
    print("\nMANUAL MODE")
    print("Enter an existing JScope command without the leading 'jscope'.")
    print("Examples: doctor | analyze ./project --verbose | graph findings.json | --help")
    print("Commands run through JScope's normal parser; no shell commands are executed.")
    last_status = 0
    while True:
        command = _ask("jscope>")
        if not command:
            continue
        if command.lower() in {"back", "menu", "exit"}:
            return None
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            print(f"Could not parse command: {exc}")
            continue
        if argv and argv[0] == "jscope":
            argv = argv[1:]
        try:
            last_status = main(argv, _show_banner=False)
        except SystemExit as exc:
            last_status = exc.code if isinstance(exc.code, int) else 0
        if last_status:
            print(f"Command exited with status {last_status}.")
