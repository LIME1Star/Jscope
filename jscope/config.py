"""Configuration. Supports a jscope.yml/json in cwd or --config path.
Users can enable/disable analyzers, set confidence threshold, output format,
concurrency, exclusions. """

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULTS: dict[str, Any] = {
    "analyzers": {
        "enabled": ["framework_detector", "endpoint_analyzer", "secret_analyzer", "router_analyzer",
                    "auth_analyzer", "authorization_analyzer", "storage_analyzer", "graphql_analyzer",
                    "service_worker_analyzer", "source_map_analyzer",
                    "html_analyzer", "openapi_analyzer", "graphql_schema_analyzer", "wasm_analyzer",
                    "dataflow_analyzer"],
    },
    "artifacts": {"enabled": True},                       # Phase 4: HTML, Vue SFC, OpenAPI, GraphQL schema, WASM
    "incremental": {"cache_dir": None, "enabled": True},
    "plugins": {"paths": [], "verified": [], "community_confidence_cap": "MEDIUM", "entry_points": True,
                "isolation": "auto", "timeout_seconds": 30, "memory_mb": 1024, "grant_read": []},
    "source_maps": {"expand": False},
    "min_confidence": "LOW",
    "output": {"format": "human", "verbose": False},
    "concurrency": 4,
    "exclude": ["**/node_modules/**"],
    "max_file_bytes": 5 * 1024 * 1024,
    "runtime": {"rate_per_second": 2.0, "max_requests": 100, "timeout_seconds": 8},
    "ai": {"enabled": False, "provider": "anthropic", "model": "claude-sonnet-5-5", "api_key_env": "ANTHROPIC_API_KEY",
           "top_n": 8, "redact_paths": True, "max_tokens": 1500},
}


@dataclass
class Config:
    data: dict[str, Any] = field(default_factory=lambda: json.loads(json.dumps(DEFAULTS)))

    @classmethod
    def load(cls, path: str | None) -> "Config":
        cfg = cls()
        if path and Path(path).exists():
            text = Path(path).read_text()
            if path.endswith((".yml", ".yaml")):
                try:
                    import yaml  # optional dependency
                    user_cfg = yaml.safe_load(text) or {}
                except ImportError:
                    raise RuntimeError("PyYAML not installed; use a .json config or `pip install pyyaml`")
            else:
                user_cfg = json.loads(text)
            cfg.data = _deep_merge(cfg.data, user_cfg)
        return cfg

    def get(self, dotted_key: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted_key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out
