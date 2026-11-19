# JScope 0.6.0: interaction redesign

Record of the audit, diagnosis, decisions, work done, and what is still open.

## 1. Audit (0.5.0, from the code)

30 subcommands in one 1,257-line `cli.py`. Analysis engines (`pipeline`, `analyzers`, `dataflow`, `core`) are independent
of the CLI and were not touched. Findings travel between commands only as a JSON file (`--save-findings`).

| Area | 0.5.0 flow | Problem (where) |
|---|---|---|
| First use | `jscope` -> hawk banner (22-line ASCII) -> mode menu -> Auto/Manual (`wizard.py`) | Auto = 3 prompts (target, profile, "Start? y/N") then `go ... --yes`. Manual = a prompt that re-types CLI commands. Two modes, neither context-aware. |
| Every command | banner printed on any TTY (`main`) | Noise on each invocation. |
| Remote target | `_confirm_target`: banner, then "press Enter" | A second confirmation for a target the user just typed. |
| After analysis | findings in `jscope-out/<slug>/findings.json` | The path is printed, not remembered. |
| Inspect | `explain <id> --findings-file <path>` | `--findings-file` mandatory; ids are `JS-0004`, not the ranks shown. |
| Graph | `graph <source>` | Re-analyzes a path, or needs a json path again. |
| Report | `report <json>` | Path again. |
| Runtime | `confirm <json> --base-url U --allow-host H --authorize-active-tests`; `verify` same plus identities | The same 3 values the user already gave `go`; `verify --finding-id` needs the id. |
| Scope/assessment | `new`, `scope-check`, `assessment-plan`, `scope-discover/review/approve` | Six commands, manifests passed by path. Separate from `go` (not connected). **Not redesigned**; see open items. |
| Workspaces | `ws-init/add/remove/list/scan/history/diff/summary` | Parallel store to `go`'s `jscope-out`; unrelated to the findings used by `explain`. Left as is (CI-oriented). |
| Plugins/doctor | `plugins`, `plugin-new`, `doctor` | Fine; unchanged. |

Root cause: the CLI has no memory, so each stage re-takes the previous stage's inputs, and the wizard papered over that
with menus.

## 2. Decisions

1. **No modes, no menus.** The wizard is removed. `jscope` with no arguments in a terminal opens a shell (`shell.py`)
   that is a loop over the *same argparse tree*. It adds three conveniences only (bare target = `go`, bare number =
   `show N`, one question before runtime traffic). A natural-language interpreter was rejected: the vocabulary is ~10
   verbs, so it adds ambiguity and no capability.
2. **Context = pointers, not data** (`session.py`). `.jscope/session.json` stores target, scope host, findings path. Findings
   stay in their own file, so evidence integrity and reproducibility do not depend on session state. A new target
   clears the old findings path; a corrupt session file is ignored, never fatal.
3. **Services shared by both interfaces** (`investigate.py`): ranking, reference resolution, route context, next
   actions, rendering. CLI and shell call the same functions; the shell has no logic of its own.
4. **Confirmation policy.** Removed: banner on every command, Enter-to-continue, mode selection, profile selection,
   "Start? y/N". Kept (these are consequences, not ceremony): `-y` for non-interactive remote runs (guards an empty
   `$VAR`), `--allow-private`, `--authorize-active-tests`, explicit `--allow-host` with an explicit `--base-url`. In the
   shell, the authorization flag is replaced by one question that shows the exact request count/host first.
5. **Scope defaults are narrow.** Runtime commands default to the investigation's own host only, which is what `go --confirm`
   already did. Nothing widens scope implicitly.
6. **Evidence-first.** `findings` has a STATE column (static / probable / confirmed / ...), `show` prints evidence class,
   verification status, limitations, evidence with file:line, and the route that reaches it. Runtime results are written
   back to the findings file with the static original preserved once (`*.static.json`).
7. **Performance.** `cli` no longer imports the analysis engine at startup (tree-sitter, 15 analyzers load only when
   analysis runs); `findings/show/status/graph/report` against a saved analysis never re-parse. No analysis caching was added.
8. **Compatibility.** All 30 prior subcommands, flags and output files are unchanged. Relaxed: `findings_file`/`source`/`--base-url`
   became optional (fall back to context); `explain` is now an alias of `show --full` (identical output); `--finding-id` also
   accepts a rank. Changed behavior: the hawk banner and the Enter prompt are gone; `jscope` with no args opens the shell.

## 3. Journey, before -> after

```
before: jscope -> 1 -> target -> 1/2 -> y -> (wait) -> note path -> explain JS-0004 --findings-file <path>
after : jscope https://app.example.com -> show 1
```

Runtime: `confirm <path> --base-url U --allow-host H --authorize-active-tests` (4 inputs) -> `confirm --dry-run` then `confirm --authorize-active-tests`; in the shell, `confirm` shows the plan and asks once.

## 4. Tests

`tests/test_investigation_ux.py`: 32 tests covering first use, context persistence (incl. subdirectory lookup, target change,
corrupt file), finding resolution (rank/id/text/ambiguous/missing), evidence/route/related output, `explain` alias parity,
unverified-never-confirmed, graph/report from context, remote `go` without prompts, scope non-inheritance with
explicit `--base-url`, authorization still required, write-back + static backup, shell flow/exit/bad input/gated confirm, parser
registry sync, all 30 old commands still registered, and that importing the CLI does not load the engine.

Environment limit: this was developed where tree-sitter could not be installed. These tests stub the engine. For the
pre-existing suite, I ran baseline and 0.6.0 side by side with the parser mocked: identical results (171 passed / 73 failed /
21 errors both ways; the failures are engine tests that need real tree-sitter and fixtures absent from the archive).
**The full suite, `python -m jscope benchmark --strict`, and a real end-to-end run have not been run and must be before release.**
`tests/test_cli_entry.py` was updated (wizard test -> shell test).

## 5. Open items (not done)

- `new` / `assessment-plan` / `scope-*` are untouched. They should fold into the investigation (`use --scope-file`, per-run
  approval recorded in the session) rather than pass manifests by path. Highest-value next step.
- `ws-*` still has its own store; unifying it with `.jscope` history/diff (`jscope diff`) is not done.
- No `jscope history`/`diff` for non-workspace investigations.
- Shell has no tab-completion of finding refs; `readline` history only.
- `observe` does not yet read target/scope from context.
- Rank numbers are stable per findings file but change after `confirm` re-scores; `findings` after a runtime step shows the new order.
