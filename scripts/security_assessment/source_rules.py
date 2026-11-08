"""Bounded source leads, not whole-program analysis or proof of exploitability.

Only run through the M3 worker inside M1 isolation for untrusted source. Python
uses the runtime AST. JS/TS/PHP use a deliberately limited lexical adapter.
"""

import ast
from pathlib import PurePosixPath
import re

from security_runtime.common import digest, require, sha256


RULES = {
    "dynamic-code": ("application", "Dynamic code execution", "Trace attacker-controlled input to this call. Replace dynamic evaluation with a data parser or explicit operation allowlist."),
    "unsafe-deserialization": ("application", "Object deserialization", "Use a non-executable data format and validate its schema; inspect every caller and trust boundary."),
    "dynamic-query": ("application", "Constructed database query", "Bind values with the database driver's parameters; allowlist structural identifiers separately."),
    "embedded-secret": ("secrets", "Literal credential assignment", "Remove the credential, revoke or rotate it if real, and load a scoped secret through the platform's secret store."),
    "session-cookie": ("identity", "Explicitly weakened session cookie", "Enable the appropriate Secure and HttpOnly protections and review SameSite, CSRF and session lifecycle in the actual deployment."),
    "sensitive-log": ("data", "Sensitive value sent to a logger", "Log an explicit safe field allowlist; exclude credentials and customer content and inspect downstream retention."),
}


def secret_name(name):
    return bool(re.fullmatch(r"(?i)(?:.*_)?(?:password|passwd|secret|token|api_?key|client_?secret|private_?key)", name))


def python_leads(source):
    tree = ast.parse(source)
    nodes = list(ast.walk(tree))
    require(len(nodes) <= 60000, "syntax inventory exceeds limit")
    results = []
    def name(node):
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute): return name(node.value) + "." + node.attr
        return ""
    for node in nodes:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and len(value.value) >= 8:
                if any(secret_name(name(target).split(".")[-1]) for target in targets):
                    results.append(("embedded-secret", node.lineno))
            for target in targets:
                key = target.slice.value if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) else name(target)
                if key in ("SESSION_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY") and isinstance(value, ast.Constant) and value.value is False:
                    results.append(("session-cookie", node.lineno))
        if not isinstance(node, ast.Call): continue
        call = name(node.func)
        if call in ("eval", "exec", "builtins.eval", "builtins.exec"):
            results.append(("dynamic-code", node.lineno))
        if call in ("pickle.loads", "pickle.load", "dill.loads", "marshal.loads"):
            results.append(("unsafe-deserialization", node.lineno))
        if call.endswith((".execute", ".executemany", ".query")) and node.args:
            query = node.args[0]
            if isinstance(query, (ast.JoinedStr, ast.BinOp)) or isinstance(query, ast.Call) and name(query.func).endswith(".format"):
                results.append(("dynamic-query", node.lineno))
        if call.startswith(("logging.", "logger.")) and any(isinstance(n, ast.Name) and secret_name(n.id) for arg in node.args for n in ast.walk(arg)):
            results.append(("sensitive-log", node.lineno))
    return results


# Strings remain typed tokens; their contents never become executable-looking
# tokens. Comments are removed, line positions retained. This is not a parser.
TOKEN = re.compile(r"(?P<space>\s+)|(?P<comment>//[^\n]*|/\*[\s\S]*?\*/|\#[^\n]*)|(?P<string>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`)|(?P<name>\$?[A-Za-z_][A-Za-z_0-9]*)|(?P<symbol>.)")


def lexical_leads(source, language):
    tokens, line = [], 1
    for match in TOKEN.finditer(source):
        kind, value = match.lastgroup, match.group()
        if kind not in ("space", "comment"): tokens.append((kind, value, line))
        line += value.count("\n")
    require(len(tokens) <= 60000, "token inventory exceeds limit")
    results = []
    for i, (kind, value, line) in enumerate(tokens):
        after = tokens[i + 1:i + 5]
        if kind == "name" and after and after[0][1] == "(":
            if value == "eval": results.append(("dynamic-code", line))
            if value == "unserialize" and language == "php": results.append(("unsafe-deserialization", line))
        if kind == "name" and secret_name(value.lstrip("$")) and len(after) >= 2 and after[0][1] == "=" and after[1][0] == "string" and len(after[1][1]) >= 10:
            results.append(("embedded-secret", line))
        if value in ("httpOnly", "secure") and len(after) >= 2 and after[0][1] == ":" and after[1][1] == "false":
            results.append(("session-cookie", line))
        if kind == "string" and value[1:-1] in ("session.cookie_secure", "session.cookie_httponly") and len(after) >= 2 and after[0][1] == "," and after[1][1] in ("0", "false", "'0'", '"0"'):
            results.append(("session-cookie", line))
    return results


def inspect_sources(contents):
    require(0 < len(contents) <= 256 and sum(map(len, contents.values())) <= 16 * 1024 * 1024, "source selection exceeds limit")
    files, leads = [], []
    for path, raw in sorted(contents.items()):
        require(len(raw) <= 1024 * 1024, "source file exceeds limit")
        language = {".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript", ".php": "php"}.get(PurePosixPath(path).suffix.lower())
        status, matches = "unsupported", []
        if language:
            try:
                source = raw.decode("utf-8-sig")
                matches = python_leads(source) if language == "python" else lexical_leads(source, language)
                status = "examined" if language == "python" else "limited_lexical"
            except (UnicodeError, SyntaxError, ValueError, RecursionError, MemoryError):
                status, matches = "inconclusive", []
        files.append({"path": path, "sha256": sha256(raw), "language": language, "status": status})
        for rule, line in sorted(set(matches)):
            domain, title, fix = RULES[rule]
            leads.append({"id": "lead-" + digest([path, line, rule])[:24], "rule": rule, "domain": domain, "path": path, "line": line, "title": title, "fix": fix, "disposition": "needs_validation"})
            require(len(leads) <= 2048, "lead inventory exceeds limit")
    return {"schema_version": 1, "adapter": "builtin-source", "files": files, "leads": leads,
            "security_verdict": "not_established", "limitations": [
                "Finite syntax rules; no interprocedural data flow, reachability or universal vulnerability coverage.",
                "Aliases, wrappers, template interpolation, mixed PHP markup and framework semantics need source-trace review.",
                "An examined file with no lead is not a security pass; dependencies and installed/deployed versions are not verified."]}
