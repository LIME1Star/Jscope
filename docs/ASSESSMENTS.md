# Domain workspaces and per-run scope

The domain workspace layer separates stored knowledge from authorization. A saved workspace, previous assessment, or discovered hostname is **not** permission to test that host in a later run.

## Create a workspace

```bash
jscope new example.com --workspace ./example-workspace
```

This initializes `.jscope-ws/` and records the normalized root domain. It performs no DNS lookups or network requests. Existing source-analysis workspace commands remain available.

## Scope file

Use one hostname per line. Blank lines and lines beginning with `#` are ignored.

```text
# Authorized for this assessment
example.com
www.example.com
api.example.com
```

The current validator accepts only DNS hostnames within the exact root domain boundary. `notexample.com` is not a subdomain of `example.com`. It rejects URLs with paths, credentials, IP literals, malformed names, and hosts outside the root domain. Validation is offline and returns rejected entries with their line numbers. The scope file is SHA-256 fingerprinted for the assessment record.

```bash
jscope scope-check example.com ./scope.txt
```

## Create an assessment manifest

Plan first, with no approved hosts:

```bash
jscope assessment-plan example.com --workspace ./example-workspace --scope-file ./scope.txt
```

Record explicit approval for every valid host in the supplied scope file for this assessment only:

```bash
jscope assessment-plan example.com --workspace ./example-workspace --scope-file ./scope.txt --approve-scope
```

Both commands are planning-only and perform no network activity. Each invocation creates a new manifest under `.jscope-ws/assessments/`, recording the root domain, scope-file hash, limits, host states, and whether approval was recorded. A discovered or merely known host remains distinct from an approved host; active scanning is not started by these commands.

## Current implementation boundary

This is the first foundation slice. It does not yet implement passive subdomain discovery, the adaptive full-scan orchestrator, or the scope-enforced network transport. Do not treat `assessment-plan` as a scanner. Those pieces must be added before the new workflow can safely launch live tests.
