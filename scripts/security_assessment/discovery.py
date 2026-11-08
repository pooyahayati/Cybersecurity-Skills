"""Bounded declaration discovery. Never import or execute target code."""

from pathlib import PurePosixPath
from itertools import islice
import re
import tomllib

from security_runtime.common import Blocked, parse


LANGUAGES = {".py": "Python", ".php": "PHP", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go", ".rs": "Rust", ".java": "Java"}
AI_PACKAGES = {"openai", "anthropic", "@anthropic-ai/sdk", "@openai/agents", "langchain", "llama-index"}


def discover(contents):
    facts, gaps, packages, languages = [], [], {}, {}
    truncated = False
    for path, raw in sorted(contents.items()):
        name = PurePosixPath(path).name
        suffix = PurePosixPath(path).suffix.lower()
        if suffix in LANGUAGES:
            languages.setdefault(LANGUAGES[suffix], []).append(path)
        if name not in {"package.json", "package-lock.json", "composer.json", "composer.lock", "pyproject.toml", "uv.lock", "poetry.lock", "version.php"}:
            continue
        # Bound the aggregate, not just each individual manifest. Preserve room
        # for language observations and keep omitted input explicitly unknown.
        if len(facts) >= 4000:
            truncated = True
            gaps.append({"path": path, "reason": "aggregate discovery limit reached; manifest not interpreted"})
            continue
        try:
            if name == "version.php":
                if path.endswith("wp-includes/version.php"):
                    match = re.search(rb"\$wp_version\s*=\s*['\"]([0-9]+\.[0-9]+(?:\.[0-9]+)?)['\"]\s*;", raw[:65536])
                    if match:
                        facts.append({"kind": "platform-marker", "name": "WordPress", "version": match[1].decode(), "version_basis": "source-assignment", "paths": [path]})
                continue
            data = tomllib.loads(raw.decode("utf-8-sig")) if name.endswith(".toml") or name in {"uv.lock", "poetry.lock"} else parse(raw)
            if not isinstance(data, dict):
                raise ValueError("object expected")
            declarations = {}
            lock_entries = []
            exact = False
            if name in {"uv.lock", "poetry.lock"}:
                exact = True
                group = data.get("package", [])
                if not isinstance(group, list): raise ValueError("invalid Python lockfile")
                for index, item in enumerate(group[:4096]):
                    if isinstance(item, dict) and isinstance(item.get("name"), str):
                        lock_entries.append((item["name"], item.get("version"), "package/" + str(index)))
                if len(group) > 4096:
                    truncated = True
                    gaps.append({"path": path, "reason": "package inventory exceeds discovery limit"})
            elif name == "package.json":
                for section in ("dependencies", "devDependencies", "optionalDependencies"):
                    group = data.get(section, {})
                    if not isinstance(group, dict): raise ValueError("invalid package declarations")
                    declarations.update(group)
            elif name == "package-lock.json":
                exact = True
                group = data.get("packages", {})
                if not isinstance(group, dict): raise ValueError("invalid lockfile")
                for key, item in islice(group.items(), 4096):
                    if isinstance(key, str) and "node_modules/" in key and isinstance(item, dict):
                        lock_entries.append((key.rsplit("node_modules/", 1)[1], item.get("version"), key))
                if len(group) > 4096:
                    truncated = True
                    gaps.append({"path": path, "reason": "package inventory exceeds discovery limit"})
            elif name == "composer.json":
                declarations = data.get("require", {})
            elif name == "composer.lock":
                exact = True
                group = data.get("packages", [])
                if not isinstance(group, list): raise ValueError("invalid lockfile")
                for index, item in enumerate(group[:4096]):
                    if isinstance(item, dict) and isinstance(item.get("name"), str):
                        lock_entries.append((item["name"], item.get("version"), "packages/" + str(index)))
                if len(group) > 4096:
                    truncated = True
                    gaps.append({"path": path, "reason": "package inventory exceeds discovery limit"})
            else:
                project = data.get("project", {})
                if not isinstance(project, dict): raise ValueError("invalid project metadata")
                requirements = project.get("dependencies", [])
                if not isinstance(requirements, list): raise ValueError("invalid dependency declarations")
                for item in requirements[:512]:
                    if isinstance(item, str):
                        match = re.fullmatch(r"([A-Za-z0-9_.-]+)([^\r\n]{0,200})", item)
                        if match: declarations[match[1].lower()] = match[2] or "unspecified"
                if len(requirements) > 512:
                    truncated = True
                    gaps.append({"path": path, "reason": "Python dependency declaration limit reached"})
            if not isinstance(declarations, dict) or len(declarations) > 4096:
                raise ValueError("invalid dependency inventory")
            entries = lock_entries if exact else [(name, value, None) for name, value in declarations.items()]
            for dependency, constraint, location in entries:
                if len(facts) >= 4000:
                    truncated = True
                    gaps.append({"path": path, "reason": "aggregate package discovery limit reached"})
                    break
                if not isinstance(dependency, str) or len(dependency) > 256 or not re.fullmatch(r"@?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?", dependency): continue
                if not isinstance(constraint, str) or not 0 < len(constraint) <= 256: continue
                if location is not None and len(location) > 512:
                    truncated = True
                    gaps.append({"path": path, "reason": "package location exceeds discovery limit"})
                    continue
                row = {"kind": "package", "name": dependency, "version": constraint, "version_basis": "lockfile" if exact else "declared-constraint", "paths": [path]}
                if location is not None: row["manifest_entry"] = location
                facts.append(row)
                packages.setdefault(dependency.lower(), []).append(row)
        except (ValueError, TypeError, UnicodeError, RecursionError, Blocked):
            gaps.append({"path": path, "reason": "manifest could not be interpreted; its capabilities remain unknown"})
    for language, paths in sorted(languages.items()):
        facts.append({"kind": "language", "name": language, "version": None, "version_basis": "selected-file-extensions", "paths": paths})
    platform = []
    wp = [f for f in facts if f["kind"] == "platform-marker"]
    if wp and "PHP" in languages and ("johnpbloch/wordpress" in packages or "roots/wordpress" in packages):
        platform.append({"name": "WordPress", "basis": "structured package declaration and selected version assignment", "version": wp[0]["version"], "runtime_verified": False})
    if packages.keys() & AI_PACKAGES:
        # A declaration routes planning, not a claim that an AI feature is deployed.
        platform.append({"name": "AI dependency", "basis": "declared package; application use requires confirmation", "version": None, "runtime_verified": False})
    return {"facts": facts, "gaps": gaps, "platform_hints": platform,
            "coverage": "selected files only", "installed_versions_verified": False,
            "inventory_truncated": truncated}
