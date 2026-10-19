from jscope.analyzers.base import ProjectContext
from jscope.analyzers.manager import AnalyzerManager
from jscope.core.evidence import EvidenceEngine
from jscope.parsing.ast_engine import ASTEngine


def ctx_for(sources: dict[str, str], frameworks=()):
    ast = ASTEngine()
    files = [ast.parse_bytes(src.encode(), path=path) for path, src in sources.items()]
    ctx = ProjectContext(files=files, ast=ast)
    for f in frameworks:
        ctx.framework_hints[f] = 1
    return ctx


def run(analyzer_classes, sources, frameworks=(), **engine_kw):
    ctx = ctx_for(sources, frameworks)
    engine = EvidenceEngine(**engine_kw)
    mgr = AnalyzerManager([c() for c in analyzer_classes])
    mgr.run(ctx, engine)
    return engine.promote(), ctx, mgr


def by_subject(findings, category=None):
    return {f.subject: f for f in findings if category is None or f.category == category}
