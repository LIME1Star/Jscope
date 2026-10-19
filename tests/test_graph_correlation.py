"""FR-05: attack-surface correlation -- findings, data-flow and evidence linked in the knowledge graph."""
from jscope.config import Config
from jscope.core.graph import EdgeKind, NodeKind
from jscope.pipeline import run_analysis


def scan(tmp_path, files, **cfg):
    for rel, src in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    c = Config()
    c.data["analyzers"]["enabled"] = ["framework_detector", "dataflow_analyzer"]
    c.data.update(cfg)
    return run_analysis([str(tmp_path)], c)


def test_finding_navigable_to_evidence_file_and_data_flow(tmp_path):
    files = {
        "src/util.js": "export function wrap(v) { return '<p>' + v + '</p>'; }\n",
        "src/main.js": "import { wrap } from './util.js';\ndocument.body.innerHTML = wrap(location.hash);\n",
    }
    res = scan(tmp_path, files)
    g = res.graph
    f = next(n for n in g.by_kind(NodeKind.FINDING) if n.attrs.get("category") == "dataflow")
    sink_edges = g.in_edges(f.id, EdgeKind.DESCRIBES)
    assert sink_edges and g.nodes[sink_edges[0].src].kind == NodeKind.DATA_SINK
    sink_id = sink_edges[0].src
    src_edges = g.in_edges(sink_id, EdgeKind.FLOWS_TO)
    assert src_edges and g.nodes[src_edges[0].src].kind == NodeKind.DATA_SOURCE
    support = g.out_edges(f.id, EdgeKind.SUPPORTED_BY)
    assert support and any(str(tmp_path / "src/main.js") in e.dst for e in support)


def test_exact_vs_heuristic_attribution_distinguished(tmp_path):
    exact = scan(tmp_path / "e", {"a.js": "el.innerHTML = location.hash;\n"})
    heur = scan(tmp_path / "h", {"a.js": "import { mystery } from 'pkg';\nel.innerHTML = mystery(location.hash);\n"})
    e_edge = next(e for e in exact.graph._edges.values() if e.kind == EdgeKind.FLOWS_TO)
    h_edge = next(e for e in heur.graph._edges.values() if e.kind == EdgeKind.FLOWS_TO)
    assert "exactness=exact" in (e_edge.note or "") and "exactness=heuristic" in (h_edge.note or "")


def test_conflicting_evidence_preserved_not_collapsed(tmp_path):
    files = {"a.js": "const v = location.hash;\nif (/^\\\\d+$/.test(v)) { el.innerHTML = v; } else { el.innerHTML = v; }\n"}
    res = scan(tmp_path, files, min_confidence="INFORMATIONAL")
    flows = res.dataflow["flows"]
    assert len(flows) == 1 and flows[0]["status"] == "candidate"
    assert any(m.get("effective_for") for m in flows[0]["mitigations"]) or flows[0]["mitigations"] == []


def test_missing_relationship_is_not_reported_as_absence_of_control(tmp_path):
    res = scan(tmp_path, {"a.js": "import { mystery } from 'pkg';\nel.innerHTML = mystery(location.hash);\n"})
    f = next(f for f in res.findings if f.category == "dataflow")
    assert any("assumption" in l or "unresolved" in l or "unknown" in l for l in f.metadata.get("limitations", []))
    assert f.metadata["flow_status"] != "sanitized"       # unresolved behaviour is never reported as "safe"
