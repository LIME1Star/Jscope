"""Application Knowledge Graph.

Pages -> components -> routes -> APIs -> auth -> roles -> storage -> services.

Per the design doc, the graph exists primarily to improve analysis accuracy
(correlating routes with the APIs they reach, finding unguarded surfaces),
not for visualization. It stores FACTS an analyzer observed in the AST, each
edge tagged with the analyzer and the evidence type that justified it. It is
not a findings channel: nothing here is user-visible as a finding unless an
analyzer ALSO proposes a Candidate through the Evidence Engine.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeKind(str, Enum):
    ROUTE = "route"
    COMPONENT = "component"
    FILE = "file"
    ENDPOINT = "endpoint"
    GUARD = "guard"
    ROLE = "role"
    STORAGE = "storage"
    SERVICE = "service"
    PAGE = "page"                      # an HTML page / Vue SFC (Phase 4)
    FORM = "form"                      # an HTML <form> (Phase 4)
    SPEC_OPERATION = "spec_operation"  # an OpenAPI operation (Phase 4)
    DATA_SOURCE = "data_source"        # a tainted input (0.5 FR-05)
    DATA_SINK = "data_sink"            # a security-sensitive sink (0.5 FR-05)
    FINDING = "finding"                # a promoted Finding, linked back into the graph (0.5 FR-05)
    RUNTIME_REQUEST = "runtime_request"  # an observed runtime request (0.5 FR-05)


class EdgeKind(str, Enum):
    RENDERS = "renders"            # route -> component | file
    CONTAINS = "contains"          # file -> component
    CALLS = "calls"                # component | file -> endpoint
    GUARDED_BY = "guarded_by"      # route -> guard
    REQUIRES_ROLE = "requires_role"  # route -> role (declared by route config)
    CHECKS_ROLE = "checks_role"    # component -> role (checked in code)
    USES_STORAGE = "uses_storage"  # component | file -> storage
    USES_SERVICE = "uses_service"  # component | file -> service
    LOADS = "loads"                # page -> file (script tag / module import)   (Phase 4)
    CONTAINS_FORM = "contains_form"  # page -> form                              (Phase 4)
    SUBMITS_TO = "submits_to"      # form -> endpoint                            (Phase 4)
    DOCUMENTS = "documents"        # spec_operation -> endpoint                  (Phase 4)
    FLOWS_TO = "flows_to"          # data_source -> data_sink                     (0.5 FR-05)
    DESCRIBES = "describes"        # data_sink | endpoint -> finding               (0.5 FR-05)
    SUPPORTED_BY = "supported_by"  # finding -> file (evidence location)           (0.5 FR-05)
    OBSERVED_AT = "observed_at"    # runtime_request -> endpoint                   (0.5 FR-05)
    VERIFIED_BY = "verified_by"    # finding -> finding (verification result attached, self-referential note) (0.5 FR-05)


# edges followed when asking "what does this route reach?"
_REACH_EDGES = {EdgeKind.RENDERS, EdgeKind.CONTAINS, EdgeKind.CALLS, EdgeKind.CHECKS_ROLE,
                EdgeKind.USES_STORAGE, EdgeKind.USES_SERVICE}


@dataclass
class Node:
    id: str
    kind: NodeKind
    label: str
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    kind: EdgeKind
    analyzer: str
    basis: str                     # EvidenceType name that justified the edge
    file: str | None = None
    line: int | None = None
    note: str | None = None


class KnowledgeGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self._edges: dict[tuple[str, str, EdgeKind], Edge] = {}
        self._out: dict[str, list[Edge]] = {}
        self._in: dict[str, list[Edge]] = {}

    # -- mutation -----------------------------------------------------------
    def add_node(self, id: str, kind: NodeKind, label: str | None = None, **attrs: Any) -> Node:
        n = self.nodes.get(id)
        if n is None:
            n = Node(id, kind, label or id, dict(attrs))
            self.nodes[id] = n
        else:
            for k, v in attrs.items():
                # list attrs accumulate (deduped); scalars: first writer wins unless falsy
                if isinstance(v, list):
                    cur = n.attrs.setdefault(k, [])
                    for item in v:
                        if item not in cur:
                            cur.append(item)
                elif not n.attrs.get(k):
                    n.attrs[k] = v
        return n

    def add_edge(self, src: str, dst: str, kind: EdgeKind, analyzer: str, basis: str,
                 file: str | None = None, line: int | None = None, note: str | None = None) -> None:
        if src not in self.nodes or dst not in self.nodes:
            raise KeyError(f"edge endpoints must exist first: {src} -> {dst}")
        key = (src, dst, kind)
        if key in self._edges:
            return
        e = Edge(src, dst, kind, analyzer, basis, file, line, note)
        self._edges[key] = e
        self._out.setdefault(src, []).append(e)
        self._in.setdefault(dst, []).append(e)

    # -- queries ------------------------------------------------------------
    def out_edges(self, node_id: str, kind: EdgeKind | None = None) -> list[Edge]:
        return [e for e in self._out.get(node_id, []) if kind is None or e.kind == kind]

    def in_edges(self, node_id: str, kind: EdgeKind | None = None) -> list[Edge]:
        return [e for e in self._in.get(node_id, []) if kind is None or e.kind == kind]

    def by_kind(self, kind: NodeKind) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind == kind]

    def reachable_from(self, node_id: str, edge_kinds: set[EdgeKind] | None = None) -> set[str]:
        edge_kinds = edge_kinds or _REACH_EDGES
        seen, q = {node_id}, deque([node_id])
        while q:
            cur = q.popleft()
            for e in self._out.get(cur, []):
                if e.kind in edge_kinds and e.dst not in seen:
                    seen.add(e.dst)
                    q.append(e.dst)
        seen.discard(node_id)
        return seen

    def routes_reaching(self, node_id: str) -> list[Node]:
        """Routes from which `node_id` (e.g. an endpoint) is reachable."""
        return [r for r in self.by_kind(NodeKind.ROUTE) if node_id in self.reachable_from(r.id)]

    def route_protection(self, route_id: str) -> dict[str, Any]:
        guards = [self.nodes[e.dst].label for e in self.out_edges(route_id, EdgeKind.GUARDED_BY)]
        roles = [self.nodes[e.dst].label for e in self.out_edges(route_id, EdgeKind.REQUIRES_ROLE)]
        return {"guards": guards, "roles": roles, "unguarded": not guards and not roles}

    def route_chains(self) -> list[dict[str, Any]]:
        """One dict per route: protection + everything reachable from it."""
        out = []
        for r in sorted(self.by_kind(NodeKind.ROUTE), key=lambda n: n.label):
            reach = self.reachable_from(r.id)
            by = lambda k: sorted(self.nodes[i].label for i in reach if self.nodes[i].kind == k)
            prot = self.route_protection(r.id)
            out.append({
                "route": r.label, "id": r.id, **prot,
                "components": by(NodeKind.COMPONENT) + by(NodeKind.FILE),
                "endpoints": by(NodeKind.ENDPOINT),
                "roles_checked": by(NodeKind.ROLE),
                "storage": by(NodeKind.STORAGE),
                "services": by(NodeKind.SERVICE),
                "framework": r.attrs.get("framework"),
                "file": r.attrs.get("file"),
            })
        return out

    # -- (de)serialization --------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [{"id": n.id, "kind": n.kind.value, "label": n.label, "attrs": n.attrs}
                      for n in self.nodes.values()],
            "edges": [{"src": e.src, "dst": e.dst, "kind": e.kind.value, "analyzer": e.analyzer,
                       "basis": e.basis, "file": e.file, "line": e.line, "note": e.note}
                      for e in self._edges.values()],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "KnowledgeGraph":
        g = cls()
        for n in d.get("nodes", []):
            g.add_node(n["id"], NodeKind(n["kind"]), n["label"], **n.get("attrs", {}))
        for e in d.get("edges", []):
            g.add_edge(e["src"], e["dst"], EdgeKind(e["kind"]), e["analyzer"], e["basis"],
                       e.get("file"), e.get("line"), e.get("note"))
        return g

    def stats(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for n in self.nodes.values():
            out[n.kind.value] = out.get(n.kind.value, 0) + 1
        out["edges"] = len(self._edges)
        return out
