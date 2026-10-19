"""Tiny WebAssembly binary reader (pure Python, no dependencies).

Extracts what recon needs, nothing more: section layout, imports, exports, memory limits, the `producers` and `name`
custom sections, and the byte range of the data section (so string hits can be tied to real data segments).
It stops at the first malformed construct and returns what it has -- never raises on hostile input.
"""

from __future__ import annotations

import re
from typing import Any

_KINDS = {0: "func", 1: "table", 2: "memory", 3: "global", 4: "tag"}
_PRINTABLE = re.compile(rb"[\x20-\x7e]{8,}")
MAX_SECTIONS = 200
MAX_ITEMS = 5000


class _Bad(Exception):
    pass


def _leb(data: bytes, i: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if i >= len(data) or shift > 63:
            raise _Bad
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def _name(data: bytes, i: int) -> tuple[str, int]:
    n, i = _leb(data, i)
    if i + n > len(data):
        raise _Bad
    return data[i:i + n].decode("utf-8", errors="replace"), i + n


def _limits(data: bytes, i: int) -> tuple[dict, int]:
    flag, i = _leb(data, i)
    lo, i = _leb(data, i)
    hi = None
    if flag & 1:
        hi, i = _leb(data, i)
    return {"min": lo, "max": hi, "shared": bool(flag & 2), "memory64": bool(flag & 4)}, i


def is_wasm(data: bytes) -> bool:
    return data[:4] == b"\x00asm"


def parse_wasm(data: bytes) -> dict[str, Any]:
    info: dict[str, Any] = {"version": None, "sections": [], "imports": [], "exports": [], "memories": [], "customs": [],
                            "producers": {}, "has_name_section": False, "data_range": None, "truncated": False}
    if not is_wasm(data) or len(data) < 8:
        info["truncated"] = True
        return info
    info["version"] = int.from_bytes(data[4:8], "little")
    i = 8
    try:
        while i < len(data) and len(info["sections"]) < MAX_SECTIONS:
            sid = data[i]
            size, j = _leb(data, i + 1)
            end = j + size
            if end > len(data):
                raise _Bad
            info["sections"].append({"id": sid, "size": size, "offset": j})
            if sid == 0:
                cname, k = _name(data, j)
                info["customs"].append(cname)
                if cname == "name":
                    info["has_name_section"] = True
                elif cname == "producers":
                    _producers(data, k, end, info)
            elif sid == 2:
                _imports(data, j, end, info)
            elif sid == 5:
                cnt, k = _leb(data, j)
                for _ in range(min(cnt, 16)):
                    lim, k = _limits(data, k)
                    info["memories"].append(lim)
            elif sid == 7:
                cnt, k = _leb(data, j)
                for _ in range(min(cnt, MAX_ITEMS)):
                    nm, k = _name(data, k)
                    kind, k = data[k], k + 1
                    _, k = _leb(data, k)
                    info["exports"].append({"name": nm, "kind": _KINDS.get(kind, str(kind))})
            elif sid == 11:
                info["data_range"] = (j, end)
            i = end
    except (_Bad, IndexError):
        info["truncated"] = True
    return info


def _producers(data: bytes, k: int, end: int, info: dict) -> None:
    try:
        nfields, k = _leb(data, k)
        for _ in range(min(nfields, 8)):
            field, k = _name(data, k)
            nvals, k = _leb(data, k)
            vals = []
            for _ in range(min(nvals, 16)):
                nm, k = _name(data, k)
                ver, k = _name(data, k)
                vals.append(f"{nm} {ver}".strip())
            info["producers"][field] = vals
    except (_Bad, IndexError):
        pass


def _imports(data: bytes, j: int, end: int, info: dict) -> None:
    cnt, k = _leb(data, j)
    for _ in range(min(cnt, MAX_ITEMS)):
        mod, k = _name(data, k)
        nm, k = _name(data, k)
        kind, k = data[k], k + 1
        if kind == 0:
            _, k = _leb(data, k)
        elif kind == 1:
            k += 1
            _, k = _limits(data, k)
        elif kind == 2:
            _, k = _limits(data, k)
        elif kind == 3:
            k += 2
        elif kind == 4:
            k += 1
            _, k = _leb(data, k)
        else:
            raise _Bad
        info["imports"].append({"module": mod, "name": nm, "kind": _KINDS.get(kind, str(kind))})


def printable_strings(data: bytes, limit: int = 20000) -> list[tuple[int, str]]:
    out = []
    for m in _PRINTABLE.finditer(data):
        out.append((m.start(), m.group().decode("ascii")))
        if len(out) >= limit:
            break
    return out
