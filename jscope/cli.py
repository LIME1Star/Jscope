"""JScope CLI. CLI-native, scriptable (PRD §4). Subcommands map 1:1 to the
operating modes in PRD §6: crawl, download, analyze, scan, report, explain."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
from pathlib import Path
from urllib.parse import urlparse

from jscope.config import Config
from jscope.core.evidence import Finding
from jscope.core.graph import KnowledgeGraph
from jscope import __version__
from jscope.pipeline import run_analysis
from jscope.reporting import human, json_report


def _emit(text: str, output: str | None) -> None:
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(text if text.endswith("\n") else text + "\n")
        print(f"[wrote {output}]", file=sys.stderr)
    else:
        print(text)


def _print_report(res, fmt: str, verbose: bool, output: str | None = None):
    if fmt in ("markdown", "md", "html", "sarif"):
        from jscope.reporting.formats import render_payload
        _emit(render_payload(json_report.payload(res.findings, res.frameworks, res.file_count, res.graph, res.diagnostics,
                            dataflow=res.dataflow, file_diagnostics=res.file_diagnostics), fmt), output)
        return
    if fmt == "json":
        _emit(json_report.render(res.findings, res.frameworks, res.file_count, res.graph, res.diagnostics,
                                dataflow=res.dataflow, file_diagnostics=res.file_diagnostics), output)
    else:
        text = human.render(res.findings, res.frameworks, res.file_count, verbose=verbose,
                            graph=res.graph, diagnostics=res.diagnostics, artifacts=res.artifact_counts)
        if res.expanded_sources:
            text += f"\n(source maps expanded: {res.expanded_sources} original source file(s) analyzed)"
        _emit(text, output)


def cmd_analyze(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    if args.min_confidence:
        config.data["min_confidence"] = args.min_confidence
    if args.format:
        config.data["output"]["format"] = args.format

    if args.expand_source_maps:
        config.data["source_maps"]["expand"] = True
    for pth in args.plugin_path or []:
        config.data["plugins"]["paths"].append(pth)
    res = run_analysis(args.paths, config)

    if res.file_count == 0:
        print("no analyzable files (JavaScript, HTML, OpenAPI, GraphQL schema, WASM) found at given path(s)", file=sys.stderr)
        return 1

    _print_report(res, config.get("output.format", "human"), args.verbose, args.output)

    if args.save_findings:
        with open(args.save_findings, "w") as f:
            json.dump(json_report.payload(res.findings, res.frameworks, res.file_count, res.graph,
                                          res.diagnostics, dataflow=res.dataflow,
                                          file_diagnostics=res.file_diagnostics), f, indent=2)
        print(f"\n[saved findings -> {args.save_findings}]", file=sys.stderr)

    return 0



# ---------------------------------------------------------------- go: the one-command entry point
def _slug(text: str) -> str:
    text = re.sub(r"^https?://", "", text)
    text = re.sub(r"[^A-Za-z0-9.-]+", "-", text).strip("-")
    return text[:80] or "target"


def _ext_for(fmt: str) -> str:
    return {"markdown": "md", "md": "md", "html": "html", "sarif": "sarif", "json": "json"}.get(fmt, "txt")


def _confirm_target(url: str, yes: bool) -> bool:
    """One-line banner + a single Enter press before any request leaves the machine. `-y` skips it;
    a non-interactive session without `-y` is refused rather than silently sent (this is the direct fix for
    'my $VAR was empty/wrong and it scanned the wrong host without telling me')."""
    host = urlparse(url).netloc or url
    try:
        ip = socket.gethostbyname(host.split(":")[0])
        resolved = f"resolves to {ip}"
    except OSError:
        resolved = "could NOT be resolved -- double check the hostname before continuing"
    print(f"\n  target : {url}", file=sys.stderr)
    print(f"  host   : {host}  ({resolved})", file=sys.stderr)
    print("  action : discover + download + analyze (read-only GET requests only; no probing without --confirm)\n", file=sys.stderr)
    if yes:
        return True
    if not sys.stdin.isatty():
        print("error: not an interactive terminal -- re-run with -y/--yes to proceed without the prompt", file=sys.stderr)
        return False
    try:
        input("  press Enter to continue, Ctrl+C to abort... ")
    except (EOFError, KeyboardInterrupt):
        print("\naborted", file=sys.stderr)
        return False
    return True


def _print_synopsis(res, out_dir: Path, report_path: Path, findings_path: Path, site_dir: Path | None) -> None:
    from jscope.reporting.priority import prioritize
    counts: dict[str, int] = {}
    for f in res.findings:
        counts[f.confidence.value] = counts.get(f.confidence.value, 0) + 1
    order = ["CONFIRMED", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    print(f"\n{len(res.findings)} finding(s): " + ", ".join(f"{k}={counts[k]}" for k in order if k in counts))
    top = sorted(prioritize(res.findings, res.graph), key=lambda t: -t[1])[:5]
    if top:
        print("\ntop priority:")
        for f, pts, why in top:
            print(f"  [{f.confidence.value:<13}] {f.category}: {f.subject}")
            if why:
                print(f"      {why[0]}")
    print(f"\nreport    : {report_path}")
    print(f"findings  : {findings_path}")
    if site_dir:
        print(f"downloaded: {site_dir}")
    print(f"\n(all output is under {out_dir}; full report: jscope report {findings_path} --format html)")


def _target_policy(url: str, prefix: str, allow_private: bool = False):
    """Transport policy bound to one target host. Loopback/private destinations stay blocked unless the user
    explicitly opts in with --allow-private (controlled local testing only)."""
    from jscope.security_transport import TransportPolicy, normalize_host
    host = urlparse(url).hostname
    if not host:
        return None
    if allow_private:
        print("note: --allow-private set; loopback/private destinations are permitted for this run", file=sys.stderr)
    return TransportPolicy(hosts={normalize_host(host)}, assessment_id=f"{prefix}-{normalize_host(host)}",
                           total_budget=100, max_response_bytes=8 * 1024 * 1024,
                           allow_loopback=allow_private, allow_private=allow_private)


def cmd_go(args: argparse.Namespace) -> int:
    """The one command most people need: point it at a URL/host or a local path and it does the right thing."""
    target = args.target
    config = Config.load(args.config)
    if args.min_confidence:
        config.data["min_confidence"] = args.min_confidence
    report_fmt = args.format or "markdown"
    local_path = Path(target)

    if local_path.exists():
        print(f"-> local path: {local_path}", file=sys.stderr)
        res = run_analysis([str(local_path)], config)
        if res.file_count == 0:
            print("no analyzable files (JavaScript, HTML, OpenAPI, GraphQL schema, WASM) found at that path", file=sys.stderr)
            return 1
        out_dir = Path(args.out) if args.out else Path("jscope-out") / _slug(local_path.name or "local")
        site_dir = None
    else:
        url = target if urlparse(target).scheme else "https://" + target
        if not _confirm_target(url, args.yes):
            return 1
        out_dir = Path(args.out) if args.out else Path("jscope-out") / _slug(urlparse(url).netloc or url)
        site_dir = out_dir / "site"
        from jscope.crawler.crawler import CrawlError, discover
        from jscope.downloader.downloader import DownloadError, download_urls
        print("[1/3] discovering ...", file=sys.stderr)
        go_policy = _target_policy(url, "go", getattr(args, "allow_private", False))
        try:
            assets = discover(url, probe=not args.no_probe, policy=go_policy)
        except CrawlError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        kinds: dict[str, int] = {}
        for a in assets:
            kinds[a.kind] = kinds.get(a.kind, 0) + 1
        print("      found " + (", ".join(f"{v} {k}" for k, v in sorted(kinds.items())) or "nothing"), file=sys.stderr)
        if not assets:
            print("nothing discovered", file=sys.stderr)
            return 1
        site_dir.mkdir(parents=True, exist_ok=True)
        url_list = site_dir / "_urls.txt"
        url_list.write_text("\n".join(a.url for a in assets) + "\n")
        print("[2/3] downloading ...", file=sys.stderr)
        try:
            results = download_urls(str(url_list), str(site_dir), policy=go_policy)
        except DownloadError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        ok = sum(1 for r in results if r.ok and not r.duplicate_of)
        failed = [r for r in results if not r.ok]
        print(f"      saved {ok} file(s)" + (f", {len(failed)} failed (run `jscope download {url_list} --out <dir>` to see why)" if failed else ""), file=sys.stderr)
        print("[3/3] analyzing ...", file=sys.stderr)
        res = run_analysis([str(site_dir)], config)
        if res.file_count == 0:
            print("downloaded files contained nothing analyzable", file=sys.stderr)
            return 1

    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = Path(args.output) if args.output else out_dir / f"report.{_ext_for(report_fmt)}"
    findings_path = Path(args.save_findings) if args.save_findings else out_dir / "findings.json"
    config.data["output"]["format"] = report_fmt
    _print_report(res, report_fmt, args.verbose, str(report_path))
    payload = json_report.payload(res.findings, res.frameworks, res.file_count, res.graph, res.diagnostics,
                            dataflow=res.dataflow, file_diagnostics=res.file_diagnostics)
    with open(findings_path, "w") as f:
        json.dump(payload, f, indent=2)
    _print_synopsis(res, out_dir, report_path, findings_path, site_dir)

    if args.confirm:
        if local_path.exists():
            print("\n--confirm needs a URL/host target, not a local path; skipping", file=sys.stderr)
            return 0
        print("\n-- runtime confirmation --", file=sys.stderr)
        if not _confirm_target(url, args.yes):
            return 0
        host = urlparse(url).netloc
        headers = _parse_headers(args.header)
        if headers is None:
            return 1
        rc, updated = _confirm_core(payload, url, args.allow_host or [host], args.rate, args.max_requests,
                                    headers, config, dry_run=False, i_have_permission=args.i_have_permission)
        if rc == 0 and updated:
            with open(findings_path, "w") as f:
                json.dump(updated, f, indent=2)
            print(f"[updated {findings_path} with runtime results]", file=sys.stderr)
        return rc
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Diagnose install problems: which copy of JScope is actually running, what's on PATH, what's missing."""
    import importlib
    import platform
    print(f"jscope  : {__version__}")
    print(f"package : {Path(__file__).resolve().parent}")
    print(f"python  : {platform.python_version()} ({sys.executable})")

    launchers, seen = [], set()
    for d in os.environ.get("PATH", "").split(os.pathsep):
        cand = Path(d) / "jscope"
        if cand.is_file() and str(cand) not in seen:
            seen.add(str(cand))
            launchers.append(cand)
    if len(launchers) > 1:
        print(f"\nWARNING: {len(launchers)} 'jscope' launchers on PATH -- the first one found wins and may be stale:")
        for lp in launchers:
            print(f"  {lp}")
        print("  Fix: pip uninstall -y jscope   (repeat until none are left), then reinstall, or just use `python -m jscope`.")
    elif launchers:
        print(f"launcher: {launchers[0]}")
    else:
        print("launcher: none on PATH -- run with `python -m jscope <command>` from the project directory")

    print("\ndependencies:")
    for mod, label in (("tree_sitter", "tree_sitter"), ("tree_sitter_javascript", "tree_sitter_javascript"),
                       ("requests", "requests"), ("bs4", "beautifulsoup4"), ("yaml", "PyYAML (optional: YAML OpenAPI specs)")):
        try:
            m = importlib.import_module(mod)
            print(f"  ok      {label:<38} {getattr(m, '__version__', '?')}")
        except ImportError:
            print(f"  MISSING {label}" + ("" if "optional" in label else "  -- pip install jscope"))

    if args.check_network:
        print()
        try:
            socket.gethostbyname("github.com")
            print("network : DNS resolution OK")
        except OSError as exc:
            print(f"network : DNS resolution FAILED ({exc})")

    print("\nIf a command's --help looks out of date, you're running a stale install. Fix:")
    print("  pip uninstall -y jscope && pip install -e . --no-deps --force-reinstall --no-cache-dir && hash -r")
    print("Or skip installing entirely: `python -m jscope <command>` always uses the current source.")
    return 0


def finding_from_dict(match: dict) -> Finding:
    from jscope.core.evidence import Evidence, EvidenceType, Confidence
    return Finding(
        id=match["id"], category=match["category"], subject=match["subject"],
        confidence=Confidence(match["confidence"]), score=match["score"],
        evidence=[Evidence(type=EvidenceType(e["type"]), description=e["description"],
                           analyzer=e["analyzer"], file=e["file"], line=e["line"],
                           snippet=e["snippet"], metadata=e["metadata"])
                  for e in match["evidence"]],
        contributing_analyzers=match["contributing_analyzers"],
        attack_surface=match["attack_surface"], suggested_test=match["suggested_test"],
        reasoning=match["reasoning"], related=match["related"], metadata=match.get("metadata", {}))


def cmd_explain(args: argparse.Namespace) -> int:
    if not args.findings_file:
        print("error: --findings-file is required (produced via `jscope analyze --save-findings`)",
              file=sys.stderr)
        return 1
    with open(args.findings_file) as f:
        data = json.load(f)
    match = next((fnd for fnd in data["findings"] if fnd["id"] == args.finding_id), None)
    if match is None:
        print(f"no finding with id {args.finding_id}", file=sys.stderr)
        return 1

    from jscope.core.evidence import Evidence, EvidenceType, Confidence
    finding = Finding(
        id=match["id"], category=match["category"], subject=match["subject"],
        confidence=Confidence(match["confidence"]), score=match["score"],
        evidence=[Evidence(type=EvidenceType(e["type"]), description=e["description"],
                            analyzer=e["analyzer"], file=e["file"], line=e["line"],
                            snippet=e["snippet"], metadata=e["metadata"])
                  for e in match["evidence"]],
        contributing_analyzers=match["contributing_analyzers"],
        attack_surface=match["attack_surface"], suggested_test=match["suggested_test"],
        reasoning=match["reasoning"], related=match["related"], metadata=match.get("metadata", {}),
    )
    print(human.render_explain(finding))
    return 0


def cmd_download(args: argparse.Namespace) -> int:
    from jscope.downloader.downloader import DownloadError, download_urls
    from jscope.security_transport import TransportPolicy, normalize_host
    try:
        if not args.allow_host:
            raise DownloadError("pass --allow-host for every explicitly authorized hostname; use `jscope scan` for target-bound discovery")
        policy = TransportPolicy(hosts={normalize_host(h) for h in args.allow_host},
                                 assessment_id="download-cli", total_budget=500,
                                 allow_loopback=args.allow_private, allow_private=args.allow_private)
        results = download_urls(args.url_file, args.out, policy=policy)
    except DownloadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    ok = sum(1 for r in results if r.ok and not r.duplicate_of)
    dup = sum(1 for r in results if r.duplicate_of)
    failed = sum(1 for r in results if not r.ok)
    print(f"downloaded={ok} duplicates_skipped={dup} failed={failed} -> {args.out}")
    for r in results:
        if not r.ok:
            print(f"  FAILED {r.url} ({r.error})", file=sys.stderr)
    return 0 if failed == 0 else 2


def cmd_crawl(args: argparse.Namespace) -> int:
    from jscope.crawler.crawler import CrawlError, discover
    try:
        assets = discover(args.url, probe=not args.no_probe,
                          policy=_target_policy(args.url if "://" in args.url else "https://" + args.url, "crawl", args.allow_private))
    except CrawlError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for a in assets:
        print(f"{a.kind:<15}{a.source:<16} {a.url}")
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(a.url for a in assets) + "\n")
        print(f"\n[wrote {len(assets)} URLs -> {args.out}]", file=sys.stderr)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Full workflow: crawl -> download -> analyze -> report, in one command (JS, HTML, specs, schemas, WASM)."""
    import tempfile
    from jscope.crawler.crawler import CrawlError, discover
    from jscope.downloader.downloader import DownloadError, download_urls
    from jscope.security_transport import TransportPolicy, normalize_host
    target = args.url if "://" in args.url else "https://" + args.url
    target_host = urlparse(target).hostname
    if not target_host:
        print("error: target URL has no valid hostname", file=sys.stderr)
        return 1
    scan_policy = _target_policy(target, "scan", getattr(args, "allow_private", False))
    print(f"[1/3] discovering from {args.url} ...", file=sys.stderr)
    try:
        assets = discover(args.url, probe=not args.no_probe, policy=scan_policy)
    except CrawlError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    kinds: dict[str, int] = {}
    for a in assets:
        kinds[a.kind] = kinds.get(a.kind, 0) + 1
    print("      found " + (", ".join(f"{v} {k}" for k, v in sorted(kinds.items())) or "nothing"), file=sys.stderr)
    if not assets:
        print("nothing discovered", file=sys.stderr)
        return 1

    tmp_ctx = None if args.out else tempfile.TemporaryDirectory(prefix="jscope_")
    try:
        root = Path(args.out) if args.out else Path(tmp_ctx.name)
        root.mkdir(parents=True, exist_ok=True)
        url_list = root / "_urls.txt"
        url_list.write_text("\n".join(a.url for a in assets) + "\n")
        print("[2/3] downloading ...", file=sys.stderr)
        try:
            results = download_urls(str(url_list), str(root), policy=scan_policy)
        except DownloadError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        ok = sum(1 for r in results if r.ok and not r.duplicate_of)
        failed = [r for r in results if not r.ok]
        print(f"      saved {ok} file(s)" + (f" -> {root}" if args.out else "") + (f", {len(failed)} failed" if failed else ""), file=sys.stderr)

        print("[3/3] analyzing ...", file=sys.stderr)
        config = Config.load(args.config)
        if args.min_confidence:
            config.data["min_confidence"] = args.min_confidence
        if args.format:
            config.data["output"]["format"] = args.format
        res = run_analysis([str(root)], config)
        if res.file_count == 0:
            print("downloaded files contained nothing analyzable", file=sys.stderr)
            return 1
        _print_report(res, config.get("output.format", "human"), args.verbose, args.output)
        if args.save_findings:
            with open(args.save_findings, "w") as f:
                json.dump(json_report.payload(res.findings, res.frameworks, res.file_count, res.graph, res.diagnostics,
                            dataflow=res.dataflow, file_diagnostics=res.file_diagnostics), f, indent=2)
            print(f"[saved findings -> {args.save_findings}]", file=sys.stderr)
    finally:
        if tmp_ctx:
            tmp_ctx.cleanup()
    return 0


def cmd_graph(args: argparse.Namespace) -> int:
    """Print the route -> component -> API -> guard/role map."""
    if args.source.endswith(".json"):
        with open(args.source) as f:
            data = json.load(f)
        if "graph" not in data:
            print("findings file has no graph (re-run `jscope analyze --save-findings`)", file=sys.stderr)
            return 1
        graph = KnowledgeGraph.from_dict(data["graph"])
    else:
        config = Config.load(args.config)
        res = run_analysis([args.source], config)
        graph = res.graph
    chains = graph.route_chains()
    if args.format == "json":
        print(json.dumps({"stats": graph.stats(), "routes": chains}, indent=2))
        return 0
    print(f"graph: {graph.stats()}")
    for c in chains:
        prot = "UNPROTECTED" if c["unguarded"] else "guards=" + ",".join(c["guards"] or ["meta"]) + (
            " roles=" + ",".join(c["roles"]) if c["roles"] else "")
        print(f"R {c['route']:<30} {prot}   [{c['file'] or '-'}]")
        for ep in c["endpoints"]:
            print(f"    -> E {ep}")
        for r in c["roles_checked"]:
            print(f"    -> role checked in code: {r}")
        for st in c["storage"]:
            print(f"    -> storage: {st}")
    return 0


def cmd_plugins(args: argparse.Namespace) -> int:
    from jscope.pipeline import core_analyzers
    from jscope.plugin.loader import PLUGIN_API_VERSION, load_plugins
    config = Config.load(args.config)
    paths = list(config.get("plugins.paths", [])) + (args.plugin_path or [])
    core = core_analyzers()
    res = load_plugins(paths, {a.name for a in core}, set(config.get("plugins.verified", [])),
                       use_entry_points=config.get("plugins.entry_points", True))
    print(f"plugin API version {PLUGIN_API_VERSION}")
    print(f"{'analyzer':<28}{'tier':<11}{'depends_on':<34}source")
    for a in core + res.analyzers:
        print(f"{a.name:<28}{a.tier:<11}{','.join(a.depends_on) or '-':<34}{res.sources.get(a.name, 'built-in')}")
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if not res.errors else 2


def cmd_plugin_new(args: argparse.Namespace) -> int:
    from jscope.plugin.loader import scaffold
    try:
        target = scaffold(args.name, args.out)
    except (ValueError, FileExistsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"created {target}\nrun it with: jscope analyze <path> --plugin-path {args.out}")
    return 0


# ---------------------------------------------------------------- workspaces (Phase 3)
def _ws(args):
    from jscope.workspace.store import Workspace
    return Workspace.open(args.workspace)


def _ws_cmd(fn):
    from jscope.workspace.store import WorkspaceError

    def wrapper(args):
        try:
            return fn(args)
        except WorkspaceError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    return wrapper


@_ws_cmd
def cmd_new(args):
    """Create a domain-centric workspace. This records a target but sends no network traffic."""
    from jscope.workspace.assessment import normalize_domain
    from jscope.workspace.store import Workspace, WorkspaceError
    try:
        domain = normalize_domain(args.target)
        root = Path(args.workspace).resolve()
        root.mkdir(parents=True, exist_ok=True)
        ws = Workspace.init(root)
        # The existing target store remains compatible with source-analysis workspaces.
        meta_path = ws.dir / "workspace.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["schema"] = "jscope-domain-workspace/1"
        meta["domain"] = {"root": domain, "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(timespec="seconds")}
        from jscope.workspace.store import _atomic_write
        _atomic_write(meta_path, meta)
        (ws.dir / "assessments").mkdir(parents=True, exist_ok=True)
        print(f"created domain workspace: {domain}")
        print(f"workspace: {ws.dir}")
        print("network activity: none")
        print("next: provide an explicit scope file for each assessment; discovery does not grant permission")
        return 0
    except WorkspaceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def cmd_scope_discover(args):
    """Inventory candidate hostnames from supplied files; never performs active network tests."""
    from jscope.passive_discovery import discover_candidates, persist_candidates
    from jscope.workspace.common import WorkspaceError
    try:
        path = Path(args.manifest)
        data = json.loads(path.read_text(encoding="utf-8"))
        candidates = discover_candidates(data["root_domain"], args.host_file or [], data.get("hosts", {}).keys())
        persist_candidates(path, candidates)
        print(json.dumps(candidates, indent=2))
        print("Passive inventory only: no active testing was started; candidates remain unapproved.")
        return 0
    except (OSError, ValueError, KeyError, WorkspaceError) as exc:
        print(f"error: {exc}", file=sys.stderr); return 2


def cmd_scope_review(args):
    from jscope.workspace.common import WorkspaceError
    try:
        data=json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        print(json.dumps({"assessment_id":data.get("assessment_id"),"root_domain":data.get("root_domain"),"hosts":data.get("hosts",{}),"approval_history":data.get("approval_history",[]),"authorization":data.get("authorization",{})},indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: manifest missing or corrupt: {exc}",file=sys.stderr); return 2


def cmd_scope_approve(args):
    from jscope.passive_discovery import approve_hosts
    from jscope.workspace.common import WorkspaceError
    try:
        data=json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        if not args.yes:
            print("Assessment:",data.get("assessment_id")); print("Hosts to approve:",", ".join(args.hosts))
            if not sys.stdin.isatty():
                print("error: non-interactive approval requires --yes",file=sys.stderr); return 2
            if input("Explicitly approve these hosts for this assessment? [y/N] ").strip().lower() != "y":
                print("approval declined"); return 1
        decision=approve_hosts(args.manifest,args.hosts)
        print(json.dumps(decision,indent=2)); return 0
    except (OSError, ValueError, KeyError, WorkspaceError) as exc:
        print(f"error: {exc}",file=sys.stderr); return 2


def cmd_assessment_plan(args):
    """Create an auditable per-run scope manifest; does not perform network activity."""
    from jscope.workspace.assessment import validate_scope_file, create_assessment_record, write_assessment
    from jscope.workspace.store import Workspace, WorkspaceError
    try:
        domain = args.domain
        scope = validate_scope_file(args.scope_file, domain)
        if not scope["valid"]:
            print(json.dumps(scope, indent=2))
            print("error: scope file has rejected entries or no valid hosts; fix it before planning", file=sys.stderr)
            return 2
        approved = scope["approved_hosts"] if args.approve_scope else []
        manifest = create_assessment_record(domain, scope["approved_hosts"], approved, {
            "max_requests": args.max_requests, "rate_per_second": args.rate,
            "depth": args.depth, "mode": "black-box-baseline",
        })
        manifest["scope_file"] = {"path": scope["path"], "sha256": scope["sha256"]}
        root = Path(args.workspace).resolve()
        ws = Workspace.open(root)
        meta = json.loads((ws.dir / "workspace.json").read_text(encoding="utf-8"))
        recorded_domain = meta.get("domain", {}).get("root")
        if recorded_domain and recorded_domain != manifest["root_domain"]:
            raise WorkspaceError(f"workspace root is {recorded_domain}, not {manifest['root_domain']}")
        out = write_assessment(root, manifest)
        print(f"assessment: {manifest['assessment_id']}")
        print(f"scope hosts: {len(scope['approved_hosts'])}")
        print(f"approved for this run: {len(approved)}")
        print(f"manifest: {out}")
        print("network activity: none (planning only)")
        if not approved:
            print("status: planned — rerun with --approve-scope to record explicit approval")
        else:
            print("status: approved — this records scope approval; it does not start testing")
        return 0
    except WorkspaceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def cmd_scope_check(args):
    """Validate a host-per-line scope file without resolving hosts or sending requests."""
    from jscope.workspace.assessment import validate_scope_file
    from jscope.workspace.store import WorkspaceError
    try:
        result = validate_scope_file(args.file, args.domain)
    except WorkspaceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 2


def cmd_ws_init(args):
    from jscope.workspace.store import Workspace
    ws = Workspace.init(args.workspace)
    print(f"initialized workspace at {ws.dir}")
    return 0


@_ws_cmd
def cmd_ws_add(args):
    _ws(args).add_target(args.name, args.paths)
    print(f"added target {args.name}")
    return 0


@_ws_cmd
def cmd_ws_remove(args):
    _ws(args).remove_target(args.name)
    print(f"removed target {args.name} (and its scan history)")
    return 0


@_ws_cmd
def cmd_ws_list(args):
    ws = _ws(args)
    for name, t in sorted(ws.targets().items()):
        h = ws.history(name)
        last = f"scans={len(h)} last={h[-1]['timestamp']}" if h else "never scanned"
        print(f"{name:<24} {last}   {', '.join(t['paths'])}")
    return 0


@_ws_cmd
def cmd_ws_scan(args):
    from jscope.workspace.diff import render_diff
    ws = _ws(args)
    config = Config.load(args.config)
    names = sorted(ws.targets()) if args.all else [args.name]
    if not args.all and not args.name:
        print("error: give a target name or --all", file=sys.stderr)
        return 1
    exit_code = 0
    for name in names:
        out = ws.scan(name, config, force=args.force)
        if out.status == "unchanged":
            print(f"[{name}] unchanged since scan {out.record['scan_id']} -- nothing re-analyzed")
            continue
        sid = out.record["scan_id"]
        print(f"[{name}] scan {sid}: {out.record['payload']['summary']['finding_count']} finding(s), "
              f"{len(out.record['files'])} file(s)")
        if out.diff is None:
            print(f"  baseline recorded (no previous scan to compare)")
        else:
            print(render_diff(out.diff))
            reasons = out.diff.regressions(args.fail_level)
            if reasons and args.fail_on_regression:
                exit_code = 3
                for r in reasons:
                    print(f"  REGRESSION: {r}", file=sys.stderr)
        if args.report:
            _print_report(out.result, config.get("output.format", "human"), args.verbose)
    return exit_code


@_ws_cmd
def cmd_ws_history(args):
    for h in _ws(args).history(args.name):
        print(f"{h['id']}  {h['timestamp']}  findings={h['finding_count']:<4} files={h['file_count']:<4} fp={h['fingerprint']}")
    return 0


@_ws_cmd
def cmd_ws_diff(args):
    from jscope.workspace.diff import diff_scans, render_diff
    ws = _ws(args)
    new = ws.load_scan(args.name, args.to)
    old = ws.load_scan(args.name, args.frm)
    d = diff_scans(old, new)
    print(json.dumps(d.to_dict(), indent=2) if args.format == "json" else render_diff(d))
    return 0


@_ws_cmd
def cmd_ws_summary(args):
    rows = _ws(args).summary()
    if args.format == "json":
        print(json.dumps(rows, indent=2))
        return 0
    for r in rows:
        if not r["scans"]:
            print(f"{r['target']:<24} never scanned")
            continue
        conf = " ".join(f"{k}={v}" for k, v in r["by_confidence"].items())
        print(f"{r['target']:<24} scans={r['scans']} findings={r['findings']} ({conf}) "
              f"unprotected_routes={r['unprotected_routes']} frameworks={','.join(r['frameworks']) or '-'}")
        if r["top"]:
            print(f"    start here: {r['top']['id']} {r['top']['subject']}  (priority {r['top']['priority']})")
    return 0


# ---------------------------------------------------------------- AI (Phase 3)
def cmd_ai(args):
    """Explain EXISTING findings from a saved findings file or a workspace scan. Opt-in by invocation."""
    from jscope.ai.explain import build_payload, explain_findings, render_ai
    from jscope.ai.providers import AIError, get_provider
    config = Config.load(args.config)
    if args.source.startswith("ws:"):
        from jscope.workspace.store import Workspace, WorkspaceError
        try:
            data = Workspace.open(args.workspace).load_scan(args.source[3:], args.scan)["payload"]
        except WorkspaceError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    else:
        with open(args.source) as f:
            data = json.load(f)
    findings = [finding_from_dict(m) for m in data["findings"]]
    graph = KnowledgeGraph.from_dict(data["graph"]) if "graph" in data else None
    acfg = config.get("ai", {})
    top_n = args.top or acfg.get("top_n", 8)
    redact = not args.send_paths and acfg.get("redact_paths", True)
    if args.dry_run:
        print(json.dumps(build_payload(findings, graph, None, top_n, redact), indent=2))
        print("[dry run: this is exactly what would be sent; nothing was sent]", file=sys.stderr)
        return 0
    try:
        provider = get_provider(acfg)
    except AIError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"[sending up to {top_n} redacted finding(s) to {provider.name}; use --dry-run to inspect]", file=sys.stderr)
    rep = explain_findings(findings, provider, graph, None, top_n, redact, acfg.get("max_tokens", 1500))
    print(render_ai(rep, findings))
    return 0 if rep.ok else 2


def _load_payload(source: str, workspace: str, scan: str) -> dict:
    if source.startswith("ws:"):
        from jscope.workspace.store import Workspace
        return Workspace.open(workspace).load_scan(source[3:], scan)["payload"]
    with open(source) as f:
        return json.load(f)


def cmd_report(args: argparse.Namespace) -> int:
    """Report Mode (PRD section 6): re-render any saved analysis without re-analyzing."""
    from jscope.workspace.store import WorkspaceError
    try:
        data = _load_payload(args.source, args.workspace, args.scan)
    except (WorkspaceError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.format == "json":
        _emit(json.dumps(data, indent=2), args.output)
    elif args.format == "human":
        findings = [finding_from_dict(m) for m in data["findings"]]
        graph = KnowledgeGraph.from_dict(data["graph"]) if "graph" in data else None
        s = data["summary"]
        _emit(human.render(findings, s["frameworks"], s["file_count"], verbose=args.verbose, graph=graph,
                           diagnostics=data.get("diagnostics")), args.output)
    else:
        from jscope.reporting.formats import render_payload
        _emit(render_payload(data, args.format), args.output)
    return 0


def _confirm_core(data: dict, base_url: str, allow_hosts: list[str], rate: float | None, max_requests: int | None,
                  headers: dict, config: Config, dry_run: bool, i_have_permission: bool) -> tuple[int, dict | None]:
    """Shared by `jscope confirm` and `jscope go --confirm`. Returns (exit_code, updated_payload_or_None)."""
    from jscope.runtime.prober import Prober, ScopeError, apply_results
    findings = [finding_from_dict(m) for m in data["findings"]]
    rt = config.get("runtime", {})
    try:
        prober = Prober(base_url, allow_hosts or [], rate or rt.get("rate_per_second", 2.0),
                        max_requests or rt.get("max_requests", 100), rt.get("timeout_seconds", 8), headers)
    except ScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1, None
    plan = prober.plan(findings)
    todo = [p for p in plan if p.url]
    print(f"plan: {len(todo)} request(s) to {prober.host} (+1 baseline), {len(plan) - len(todo)} skipped", file=sys.stderr)
    for p in plan:
        print(f"  {'SEND' if p.url else 'SKIP'} {p.method:<7} {p.url or p.subject}" + (f"   ({p.skip_reason})" if p.skip_reason else ""))
    if dry_run:
        print("[dry run: nothing was sent]", file=sys.stderr)
        return 0, None
    if not i_have_permission:
        print("error: refusing to send requests without --i-have-permission (you are authorized to test this host). "
              "Use --dry-run to review the plan first.", file=sys.stderr)
        return 1, None
    _, results = prober.run(findings)
    for r in results:
        print(f"  {r.verdict:<17} {r.method:<7} {r.subject}  {r.reason}")
    updated = apply_results(findings, results)
    by_id = {f.id: f for f in updated}
    for o in findings:
        n = by_id[o.id]
        if n.confidence != o.confidence:
            print(f"  {o.id} {o.subject}: {o.confidence.value} -> {n.confidence.value}")
    data = dict(data)
    data["findings"] = [f.to_dict() for f in updated]
    data["runtime"] = {"base_url": prober.base, "requests_sent": prober.sent,
                       "results": [{"id": r.finding_id, "subject": r.subject, "method": r.method, "status": r.status,
                                    "verdict": r.verdict, "reason": r.reason} for r in results]}
    graph = KnowledgeGraph.from_dict(data["graph"]) if "graph" in data else None
    from jscope.reporting.priority import prioritize
    data["priority"] = [{"id": f.id, "priority": pts, "reasons": why} for f, pts, why in prioritize(updated, graph)]
    return 0, data


def _parse_headers(raw: list[str] | None) -> dict | None:
    headers = {}
    for h in raw or []:
        if ":" not in h:
            print(f"error: --header must look like 'Name: value', got {h!r}", file=sys.stderr)
            return None
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def _verify_core(data: dict, base_url: str, allow_hosts: list[str], identities: list, authorize: bool,
                 category: str | None, finding_ids: list[str] | None, config: Config, allow_private: bool) -> tuple[int, dict | None]:
    """Shared by `jscope verify`. Returns (exit_code, updated_payload_or_None)."""
    from jscope.runtime.scope import EmergencyStop, ScopePolicy
    from jscope.verify.engine import VerificationEngine
    rt = config.get("runtime", {})
    policy = ScopePolicy(allow_hosts=set(allow_hosts), allow_private=allow_private,
                         rate_per_second=rt.get("rate_per_second", 2.0), max_requests=rt.get("max_requests", 100),
                         timeout=rt.get("timeout_seconds", 8.0), stop=EmergencyStop())
    eng = VerificationEngine(policy, base_url, identities=identities, authorized=authorize)
    targets = [f for f in data["findings"] if (category is None or f["category"] == category)
              and (finding_ids is None or f["id"] in finding_ids)
              and f.get("metadata", {}).get("verification_status", "unverified") != "confirmed"]
    if not targets:
        print("no eligible findings matched the given filters (already-confirmed findings are skipped)", file=sys.stderr)
    if not authorize:
        print("NOTE: running without --authorize-active-tests; every result will be 'rejected' (authorization required)", file=sys.stderr)
    results = []
    for f in targets:
        r = eng.verify(f)
        results.append(r)
        f.setdefault("metadata", {})["verification"] = r.to_metadata()
        print(f"  {r.status:<12} {f['id']:<10} {f['category']}: {f['subject'][:70]}  [{r.procedure}]")
    data = dict(data)
    print(f"\nverified {len(results)} finding(s): " +
          ", ".join(f"{s}={sum(1 for r in results if r.status == s)}" for s in ("confirmed", "probable", "inconclusive", "rejected", "unverified")),
          file=sys.stderr)
    return 0, data


def cmd_verify(args: argparse.Namespace) -> int:
    """FR-04: attempt to reproduce selected candidate vulnerabilities. Requires --authorize-active-tests."""
    from jscope.verify.engine import TestIdentity
    config = Config.load(args.config)
    with open(args.findings_file) as f:
        data = json.load(f)
    identities = []
    for spec in args.identity or []:
        if "=" not in spec:
            print(f"error: --identity must be NAME=header:value,header:value (got {spec!r})", file=sys.stderr)
            return 1
        name, rest = spec.split("=", 1)
        headers = {}
        for pair in rest.split(","):
            if ":" not in pair:
                print(f"error: malformed header in --identity {spec!r}", file=sys.stderr)
                return 1
            k, v = pair.split(":", 1)
            headers[k.strip()] = v.strip()
        identities.append(TestIdentity(name, headers=headers))
    role_map = {}
    for spec in args.identity_role or []:
        if "=" in spec:
            role_map[spec.split("=", 1)[0]] = spec.split("=", 1)[1]
    for ident in identities:
        if ident.name in role_map:
            ident.role = role_map[ident.name]
    rc, updated = _verify_core(data, args.base_url, args.allow_host or [], identities, args.authorize_active_tests,
                               args.category, args.finding_id, config, args.allow_private)
    if rc == 0 and updated and args.out:
        with open(args.out, "w") as fh:
            json.dump(updated, fh, indent=2)
        print(f"[wrote {args.out}]", file=sys.stderr)
    return rc


def cmd_observe(args: argparse.Namespace) -> int:
    """FR-03: runtime browser observation, saved as a trace; optionally correlated against a findings payload."""
    from jscope.runtime.observe import Scenario, correlate, novel_routes, observe
    from jscope.runtime.scope import EmergencyStop, ScopePolicy
    scenario = Scenario.load(args.scenario) if args.scenario else Scenario.default(args.path or "/")
    policy = ScopePolicy(allow_hosts=set(args.allow_host or []), allow_private=args.allow_private,
                         rate_per_second=args.rate, max_requests=args.max_requests, stop=EmergencyStop())
    trace = observe(args.base_url, policy, scenario, driver=args.driver)
    print(f"driver={trace.driver} status={trace.status} events={len(trace.events)}", file=sys.stderr)
    for r in trace.incomplete_reasons:
        print(f"  ! {r}", file=sys.stderr)
    out = trace.to_dict()
    if args.findings_file:
        with open(args.findings_file) as f:
            payload = json.load(f)
        out["correlation"] = correlate(trace, payload)
        out["novel_routes"] = novel_routes(trace, payload)
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(out, fh, indent=2)
        print(f"[wrote {args.out}]", file=sys.stderr)
    else:
        print(json.dumps(out, indent=2))
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    """FR-06: run the real-world accuracy benchmark suite and report precision/recall/FP/FN by vulnerability class."""
    from jscope.benchmark.runner import run_benchmark
    report = run_benchmark(check_reproducibility=not args.no_reproducibility_check)
    d = report.to_dict()
    print(f"ran {d['entries']} fixture(s) ({d['difficult_entries']} difficult, reported separately) in {d['duration_s']}s, "
          f"peak memory {d['peak_memory_mb']}MB, reproducible={d['reproducible']}", file=sys.stderr)
    for cls, m in d["by_class"].items():
        print(f"  {cls:<20} TP={m['true_positives']} FP={m['false_positives']} FN={m['false_negatives']} "
              f"TN={m['true_negatives']}  precision={m['precision']} recall={m['recall']}")
    print(f"overall: precision={d['overall']['precision']} recall={d['overall']['recall']}", file=sys.stderr)
    regressions = []
    if args.baseline:
        with open(args.baseline) as f:
            baseline = json.load(f)
        regressions = report.regressions_against(baseline)
        for r in regressions:
            print(f"  REGRESSION: {r['name']} was {r['was']}, now {r['now']}", file=sys.stderr)
    if args.out:
        with open(args.out, "w") as f:
            json.dump(d, f, indent=2)
        print(f"[wrote {args.out}]", file=sys.stderr)
    fail = (d["overall"]["false_positives"] > 0 or d["overall"]["false_negatives"] > 0 or regressions
           or (not d["reproducible"] and d["reproducible"] is not None))
    return 1 if (fail and args.strict) else 0


def cmd_confirm(args: argparse.Namespace) -> int:
    """Opt-in runtime confirmation: safe methods only, allow-listed hosts only. See docs/RUNTIME.md."""
    config = Config.load(args.config)
    with open(args.findings_file) as f:
        data = json.load(f)
    headers = _parse_headers(args.header)
    if headers is None:
        return 1
    rc, updated = _confirm_core(data, args.base_url, args.allow_host or [], args.rate, args.max_requests,
                                headers, config, args.dry_run, args.i_have_permission)
    if rc == 0 and updated and args.out:
        with open(args.out, "w") as fh:
            json.dump(updated, fh, indent=2)
        print(f"[wrote {args.out}; {updated['runtime']['requests_sent']} request(s) sent]", file=sys.stderr)
    return rc


# Every subcommand name the parser below registers. Used to decide whether a bare `jscope <arg>` should be
# rewritten to `jscope go <arg>` -- kept as a literal set (not derived from the parser) so it is cheap to check
# before argparse runs at all; test_cli_entry.py asserts it stays in sync with the real subparser list.
KNOWN_COMMANDS = {
    "analyze", "explain", "report", "confirm", "verify", "observe", "benchmark", "graph", "plugins", "plugin-new", "download", "crawl", "scan",
    "go", "doctor", "new", "scope-check", "assessment-plan", "scope-discover", "scope-review", "scope-approve", "ws-init", "ws-add", "ws-remove", "ws-list", "ws-scan", "ws-history", "ws-diff", "ws-summary", "ai",
}


def _rewrite_bare_target(argv: list[str]) -> list[str]:
    """`jscope <target>` (no subcommand) is shorthand for `jscope go <target>`. Only rewrites when the first
    token isn't a flag, isn't a known subcommand, and there's at least one argument -- so `jscope`, `jscope -h`
    and `jscope analyze ...` are all untouched."""
    if not argv or argv[0].startswith("-") or argv[0] in KNOWN_COMMANDS:
        return argv
    return ["go", *argv]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="jscope", description="JavaScript Intelligence Framework. Run with no subcommand "
                                "and a target (`jscope <url-or-path>`) to just do the right thing.")
    p.add_argument("--version", "-V", action="version", version=f"jscope {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    pg2 = sub.add_parser("go", help="do the right thing: analyze a local path, or crawl+download+analyze a URL/host")
    pg2.add_argument("target", help="a URL/host to scan, or a local file/directory to analyze")
    pg2.add_argument("--out", default=None, help="output directory (default: jscope-out/<target>/)")
    pg2.add_argument("--output", "-o", default=None, help="override the report file path")
    pg2.add_argument("--save-findings", default=None, help="override the findings JSON path")
    pg2.add_argument("--format", choices=["human", "json", "markdown", "html", "sarif"], default=None,
                     help="report format (default: markdown)")
    pg2.add_argument("--min-confidence", choices=["CONFIRMED", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"], default=None)
    pg2.add_argument("--allow-private", action="store_true", help="permit loopback/private destinations (controlled local testing only)")
    pg2.add_argument("--no-probe", action="store_true", help="skip well-known OpenAPI/GraphQL spec paths (remote targets only)")
    pg2.add_argument("-y", "--yes", action="store_true", help="skip the target-confirmation prompt (required in non-interactive sessions)")
    pg2.add_argument("--confirm", action="store_true", help="after analyzing, also run opt-in runtime confirmation (still needs --i-have-permission to send)")
    pg2.add_argument("--allow-host", action="append", help="host(s) allowed for --confirm (default: the target's own host)")
    pg2.add_argument("--i-have-permission", action="store_true", help="required for --confirm to actually send requests")
    pg2.add_argument("--header", action="append", help="extra header for --confirm, e.g. 'Cookie: session=...'")
    pg2.add_argument("--rate", type=float, default=None)
    pg2.add_argument("--max-requests", type=int, default=None)
    pg2.add_argument("--verbose", action="store_true")
    pg2.add_argument("--config", default=None)
    pg2.set_defaults(func=cmd_go)

    pnw = sub.add_parser("new", help="create a domain-centric workspace (no network traffic)")
    pnw.add_argument("target", help="root DNS domain, e.g. example.com")
    pnw.add_argument("--workspace", default=".", help="workspace directory (default: current directory)")
    pnw.set_defaults(func=cmd_new)

    psd = sub.add_parser("scope-discover", help="passively inventory candidate hostnames from host files; no probing")
    psd.add_argument("manifest", help="current assessment JSON manifest")
    psd.add_argument("--host-file", action="append", default=[], help="host-per-line candidate file (repeatable)")
    psd.set_defaults(func=cmd_scope_discover)

    psr = sub.add_parser("scope-review", help="show current assessment scope and approval history")
    psr.add_argument("manifest")
    psr.set_defaults(func=cmd_scope_review)

    psa = sub.add_parser("scope-approve", help="explicitly approve known hosts for one assessment")
    psa.add_argument("manifest")
    psa.add_argument("hosts", nargs="+", help="candidate hostnames already recorded as known")
    psa.add_argument("--yes", action="store_true", help="explicit non-interactive approval")
    psa.set_defaults(func=cmd_scope_approve)

    pap = sub.add_parser("assessment-plan", help="create a per-run scope manifest; planning only, no network traffic")
    pap.add_argument("domain", help="workspace root domain")
    pap.add_argument("--scope-file", required=True, help="host-per-line list of authorized in-domain hosts")
    pap.add_argument("--workspace", default=".", help="directory containing .jscope-ws")
    pap.add_argument("--approve-scope", action="store_true", help="record explicit approval of every valid host in this scope file for this run")
    pap.add_argument("--max-requests", type=int, default=500)
    pap.add_argument("--rate", type=float, default=2.0)
    pap.add_argument("--depth", choices=["baseline", "deep"], default="deep")
    pap.set_defaults(func=cmd_assessment_plan)

    psc = sub.add_parser("scope-check", help="validate an explicit host-per-line scope file without network traffic")
    psc.add_argument("domain", help="root domain for this assessment")
    psc.add_argument("file", help="text file containing authorized hostnames, one per line")
    psc.set_defaults(func=cmd_scope_check)

    pdoc = sub.add_parser("doctor", help="diagnose install problems (which jscope is running, what's missing)")
    pdoc.add_argument("--check-network", action="store_true", help="also check DNS resolution")
    pdoc.set_defaults(func=cmd_doctor)

    pa = sub.add_parser("analyze", help="analyze existing JS files/directories")
    pa.add_argument("paths", nargs="+", help="files or directories to analyze")
    pa.add_argument("--config", default=None)
    pa.add_argument("--format", choices=["human", "json", "markdown", "html", "sarif"], default=None)
    pa.add_argument("--output", "-o", default=None, help="write the report to this file instead of stdout")
    pa.add_argument("--min-confidence", choices=["CONFIRMED", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
                     default=None)
    pa.add_argument("--verbose", action="store_true")
    pa.add_argument("--save-findings", default=None, help="path to save findings JSON for `jscope explain` / `jscope graph`")
    pa.add_argument("--expand-source-maps", action="store_true",
                    help="analyze original sources recovered from on-disk source maps (offline)")
    pa.add_argument("--plugin-path", action="append", help="directory or file of analyzer plugins (repeatable)")
    pa.set_defaults(func=cmd_analyze)

    pe = sub.add_parser("explain", help="show full evidence chain for one finding")
    pe.add_argument("finding_id")
    pe.add_argument("--findings-file", required=True)
    pe.set_defaults(func=cmd_explain)

    pr = sub.add_parser("report", help="re-render a saved analysis as human/json/markdown/html/sarif (no re-analysis)")
    pr.add_argument("source", help="findings .json, or ws:<target> for a workspace scan")
    pr.add_argument("--format", choices=["human", "json", "markdown", "html", "sarif"], default="markdown")
    pr.add_argument("--output", "-o", default=None)
    pr.add_argument("--workspace", default="."); pr.add_argument("--scan", default="latest")
    pr.add_argument("--verbose", action="store_true")
    pr.set_defaults(func=cmd_report)

    pk = sub.add_parser("confirm", help="OPT-IN: probe endpoint findings with safe methods to confirm they respond (docs/RUNTIME.md)")
    pk.add_argument("findings_file", help="saved with `jscope analyze --save-findings`")
    pk.add_argument("--base-url", required=True, help="origin to test, e.g. https://app.example.com")
    pk.add_argument("--allow-host", action="append", help="host[:port] you are authorized to test (repeatable, required)")
    pk.add_argument("--i-have-permission", action="store_true", help="required to actually send; confirms you may test the host")
    pk.add_argument("--dry-run", action="store_true", help="print the request plan and send nothing")
    pk.add_argument("--header", action="append", help="extra request header 'Name: value' (e.g. a session cookie you own)")
    pk.add_argument("--rate", type=float, default=None, help="requests per second (default 2)")
    pk.add_argument("--max-requests", type=int, default=None, help="hard cap (default 100)")
    pk.add_argument("--out", default=None, help="write the re-scored findings JSON here")
    pk.add_argument("--config", default=None)
    pk.set_defaults(func=cmd_confirm)

    pv = sub.add_parser("verify", help="OPT-IN: attempt to reproduce candidate vulnerabilities (FR-04, docs/VERIFICATION.md)")
    pv.add_argument("findings_file", help="saved with `jscope analyze --save-findings`")
    pv.add_argument("--base-url", required=True, help="origin to test, e.g. https://app.example.com")
    pv.add_argument("--allow-host", action="append", help="host[:port] you are authorized to test (repeatable, required)")
    pv.add_argument("--authorize-active-tests", action="store_true", help="required to actually run tests; confirms you may test the host")
    pv.add_argument("--allow-private", action="store_true", help="permit loopback/private destinations (controlled local test)")
    pv.add_argument("--category", default=None, help="only verify findings in this category (e.g. dataflow, idor)")
    pv.add_argument("--finding-id", action="append", dest="finding_id", default=None, help="only verify this finding id (repeatable)")
    pv.add_argument("--identity", action="append", help="test identity NAME=Header:value,Header2:value2 (repeatable; need >=2 for authz checks)")
    pv.add_argument("--identity-role", action="append", default=None, help="NAME=role for an --identity (e.g. admin=admin)")
    pv.add_argument("--out", default=None, help="write the updated findings JSON (with verification metadata) here")
    pv.add_argument("--config", default=None)
    pv.set_defaults(func=cmd_verify, identity_role=None)

    po = sub.add_parser("observe", help="OPT-IN: runtime browser observation, correlated with static findings (FR-03)")
    po.add_argument("base_url", help="origin to observe, e.g. https://app.example.com")
    po.add_argument("--path", default="/", help="path to navigate to if no --scenario is given (default /)")
    po.add_argument("--scenario", default=None, help="JSON scenario file: {\"steps\": [{\"goto\": \"/\"}, {\"click\": \"#x\"}]}")
    po.add_argument("--allow-host", action="append", help="host[:port] you are authorized to observe (repeatable, required)")
    po.add_argument("--allow-private", action="store_true")
    po.add_argument("--driver", choices=["auto", "playwright", "http"], default="auto")
    po.add_argument("--rate", type=float, default=2.0)
    po.add_argument("--max-requests", type=int, default=200)
    po.add_argument("--findings-file", default=None, help="correlate the trace against a saved findings JSON")
    po.add_argument("--out", default=None, help="write the trace JSON here (default: print to stdout)")
    po.set_defaults(func=cmd_observe)

    pb = sub.add_parser("benchmark", help="FR-06: run the accuracy benchmark suite (precision/recall by vuln class, CI gate)")
    pb.add_argument("--out", default=None, help="write the full benchmark report JSON here")
    pb.add_argument("--baseline", default=None, help="a previous benchmark report JSON to diff against for regressions")
    pb.add_argument("--no-reproducibility-check", action="store_true", help="skip the repeated-run determinism check (faster)")
    pb.add_argument("--strict", action="store_true", help="exit 1 if any false positive/negative, regression, or non-determinism is found")
    pb.set_defaults(func=cmd_benchmark)

    pg = sub.add_parser("graph", help="print the route -> component -> API -> guard map")
    pg.add_argument("source", help="a path to analyze, or a findings .json saved with --save-findings")
    pg.add_argument("--config", default=None)
    pg.add_argument("--format", choices=["human", "json"], default="human")
    pg.set_defaults(func=cmd_graph)

    pl = sub.add_parser("plugins", help="list core and loaded plugin analyzers with trust tier")
    pl.add_argument("--config", default=None)
    pl.add_argument("--plugin-path", action="append")
    pl.set_defaults(func=cmd_plugins)

    pn = sub.add_parser("plugin-new", help="scaffold a new analyzer plugin")
    pn.add_argument("name")
    pn.add_argument("--out", default="./jscope_plugins")
    pn.set_defaults(func=cmd_plugin_new)

    pd = sub.add_parser("download", help="download JS from a URL list")
    pd.add_argument("url_file")
    pd.add_argument("--out", default="./jscope_project")
    pd.add_argument("--allow-host", action="append", default=[],
                    help="explicitly authorized hostname (repeat for each host); unguarded downloads are refused")
    pd.add_argument("--allow-private", action="store_true", help="permit loopback/private destinations (controlled local testing only)")
    pd.set_defaults(func=cmd_download)

    pc = sub.add_parser("crawl", help="discover JS assets from a live site")
    pc.add_argument("url")
    pc.add_argument("--out", default=None, help="write discovered URLs to this file")
    pc.add_argument("--allow-private", action="store_true", help="permit loopback/private destinations (controlled local testing only)")
    pc.add_argument("--no-probe", action="store_true", help="do not request well-known spec paths (openapi.json, swagger.json, ...)")
    pc.set_defaults(func=cmd_crawl)

    ps = sub.add_parser("scan", help="full workflow: crawl -> download -> analyze -> report")
    ps.add_argument("url")
    ps.add_argument("--config", default=None)
    ps.add_argument("--verbose", action="store_true")
    ps.add_argument("--out", default=None, help="keep the downloaded project in this directory (default: temporary, deleted after)")
    ps.add_argument("--format", choices=["human", "json", "markdown", "html", "sarif"], default=None)
    ps.add_argument("--output", "-o", default=None, help="write the report to this file")
    ps.add_argument("--save-findings", default=None, help="save findings JSON (for report/confirm/explain/graph)")
    ps.add_argument("--min-confidence", choices=["CONFIRMED", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"], default=None)
    ps.add_argument("--allow-private", action="store_true", help="permit loopback/private destinations (controlled local testing only)")
    ps.add_argument("--no-probe", action="store_true", help="do not request well-known spec paths")
    ps.set_defaults(func=cmd_scan)

    # --- workspaces
    def wsp(name, help_, fn):
        q = sub.add_parser(name, help=help_)
        q.add_argument("--workspace", default=".", help="directory containing .jscope-ws (default: .)")
        q.set_defaults(func=fn)
        return q

    wsp("ws-init", "create a workspace here", cmd_ws_init)
    q = wsp("ws-add", "register a target (name + one or more paths)", cmd_ws_add)
    q.add_argument("name"); q.add_argument("paths", nargs="+")
    q = wsp("ws-remove", "delete a target and its history", cmd_ws_remove)
    q.add_argument("name")
    wsp("ws-list", "list targets", cmd_ws_list)
    q = wsp("ws-scan", "scan a target (or --all); skips if nothing changed, else diffs vs previous", cmd_ws_scan)
    q.add_argument("name", nargs="?"); q.add_argument("--all", action="store_true")
    q.add_argument("--config", default=None); q.add_argument("--force", action="store_true")
    q.add_argument("--report", action="store_true", help="also print the full report")
    q.add_argument("--verbose", action="store_true")
    q.add_argument("--fail-on-regression", action="store_true", help="exit 3 on new/raised findings or lost route protection")
    q.add_argument("--fail-level", default="HIGH", choices=["CONFIRMED", "HIGH", "MEDIUM", "LOW"])
    q = wsp("ws-history", "list scans for a target", cmd_ws_history)
    q.add_argument("name")
    q = wsp("ws-diff", "diff two scans of a target (default: previous -> latest)", cmd_ws_diff)
    q.add_argument("name"); q.add_argument("--from", dest="frm", default="previous")
    q.add_argument("--to", default="latest"); q.add_argument("--format", choices=["human", "json"], default="human")
    q = wsp("ws-summary", "one-line status per target", cmd_ws_summary)
    q.add_argument("--format", choices=["human", "json"], default="human")

    # --- AI
    q = sub.add_parser("ai", help="AI commentary over existing findings (opt-in; secrets redacted)")
    q.add_argument("source", help="findings .json, or ws:<target> for a workspace scan")
    q.add_argument("--workspace", default="."); q.add_argument("--scan", default="latest")
    q.add_argument("--config", default=None); q.add_argument("--top", type=int, default=None)
    q.add_argument("--dry-run", action="store_true", help="print exactly what would be sent, send nothing")
    q.add_argument("--send-paths", action="store_true", help="include full local file paths (default: basenames)")
    q.set_defaults(func=cmd_ai)

    return p


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    argv = _rewrite_bare_target(argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
