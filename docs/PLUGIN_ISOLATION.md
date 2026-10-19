# Plugin execution security (FR-09)

By default (`plugins.isolation: "auto"`) a plugin's code is imported and run **inside a separate, restricted Python
process** (`jscope -I` child), not inside the JScope process. Set a plugin's name in `plugins.verified` to run it
in-process instead (full trust); `plugins.isolation: "none"` runs everything in-process (loud warning in diagnostics);
`"always"` sandboxes every plugin regardless of `verified`. Entry-point (installed-package) plugins always run
in-process -- installing a package is already a trust decision.

## What the sandbox restricts
A Python [audit hook](https://docs.python.org/3/library/audit_events.html) (installed before the plugin's own code
runs, and un-removable) denies: creating sockets or doing DNS, spawning processes (`subprocess`, `os.system`,
`os.exec*`, `os.fork`), `ctypes`, writing/deleting/renaming/chmod-ing anything, and reading outside an explicit
allow-list of roots (JScope's own install, the plugin's own directory, and anything in `plugins.grant_read`). POSIX
resource limits additionally cap CPU time, address space, open file descriptors and max file size (0 -- no file can be
created at all). The child gets a scrubbed environment (no inherited secrets) and an empty temporary cwd.

This is **defence in depth, not a hard sandbox** (no seccomp/namespaces/containers) -- see the "what this isn't"
section below.

## What happens on violation
A denied call raises inside the plugin; the manager records it the same way as any other analyzer crash
(`"[name] crashed: ..."`), plus a `[plugin-isolation] ... attempted forbidden operations: ...` diagnostic naming
exactly what was attempted. The run's outcome (`ok | error | timeout | resource_exhausted | policy_violation |
invalid_output`) is recorded per-plugin in `AnalysisResult.plugin_runs` (`version`, `tier`, `isolation`, `duration_s`,
`violations`).

## What the sandbox does NOT change
Plugin output still goes through the same propose/promote boundary as every analyzer (`jscope/analyzers/manager.py`):
a plugin can never emit a `Finding`, `CROSS_ANALYZER_AGREEMENT`, or `RUNTIME_*` evidence, and community-tier plugins
are still capped at `plugins.community_confidence_cap`.

## Platform guarantees
- **Linux/macOS**: audit hook + `resource` rlimits (CPU/memory/fds/file-size) + process isolation.
- **Windows**: audit hook + process isolation only; the `resource` module doesn't exist, so CPU/memory rlimits are not
  enforced at the OS level there -- rely on the wall-clock `timeout_seconds` (SIGKILL-equivalent process termination).
