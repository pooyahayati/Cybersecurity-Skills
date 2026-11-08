"""Finite configuration leads and minimized container/scanner observations."""

from pathlib import PurePosixPath
import re

from security_runtime.common import digest, parse, relpath, require, sha256


RULES = {
    "privileged": ("Privileged workload", "Remove privileged mode and grant only required capabilities."),
    "host-network": ("Host network shared", "Use an isolated network unless the deployment explicitly requires host networking."),
    "root-user": ("Root or unspecified workload user", "Select a dedicated non-root user and verify required file access."),
    "docker-socket": ("Host control socket exposed", "Remove the Docker socket mount from the workload."),
    "secret-config": ("Potential credential embedded in configuration", "Use a scoped secret reference; rotate any credential actually exposed."),
    "public-storage": ("Public storage declaration", "Restrict storage access and verify the intended public/private data boundary."),
    "wildcard-iam": ("Wildcard permission declaration", "Restrict actions and resources to the workload's documented needs."),
    "open-admin": ("Administrative port open to all addresses", "Restrict management ingress to explicitly authorized networks."),
    "ci-write-all": ("Broad workflow token permission", "Give each job only the permissions its steps require."),
    "ci-unpinned": ("Mutable third-party action reference", "Review the current action and bind execution to its immutable commit."),
    "ci-secret-output": ("Workflow may print a secret", "Remove secret expansion from output and inspect retained build logs privately."),
}


def lead(rule, path, line=1):
    title, fix = RULES[rule]
    return {"id": "infra-" + digest([rule, path, line])[:24], "rule": rule, "path": path,
            "line": line, "title": title, "fix": fix, "disposition": "needs_validation"}


def inspect_files(contents):
    files, leads = [], []
    for path, raw in sorted(contents.items()):
        status = "unsupported"
        try:
            text = raw.decode("utf-8")
            if path.endswith(".json"):
                obj = parse(raw, 1024 * 1024)
                recognized = isinstance(obj, dict) and (path.endswith((".tf.json", ".tfplan.json"))
                    or obj.get("kind") in {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Service"}
                    or isinstance(obj.get("Statement"), list) or "format_version" in obj and "resource_changes" in obj)
                if not recognized:
                    files.append({"path": path, "sha256": sha256(raw), "status": "unsupported"})
                    continue
                status = "limited_structured"
                stack, nodes = [obj], 0
                while stack:
                    value = stack.pop()
                    nodes += 1
                    require(nodes <= 30000, "configuration exceeds traversal bound")
                    if isinstance(value, list): stack.extend(value)
                    if not isinstance(value, dict): continue
                    stack.extend(value.values())
                    tests = {"privileged": value.get("privileged") is True,
                        "host-network": value.get("hostNetwork") is True,
                        "root-user": value.get("runAsUser") == 0 and type(value.get("runAsUser")) is int,
                        "docker-socket": value.get("path") in {"/var/run/docker.sock", "/run/docker.sock"},
                        "public-storage": value.get("acl") in {"public-read", "public-read-write"} if isinstance(value.get("acl"), str) else False,
                        "wildcard-iam": value.get("Effect") == "Allow" and (value.get("Action") == "*" or value.get("Resource") == "*"),
                        "open-admin": value.get("from_port") in {22, 3389} and isinstance(value.get("cidr_blocks"), list) and "0.0.0.0/0" in value["cidr_blocks"],
                        "secret-config": isinstance(value.get("name"), str) and re.search(r"(?i)(?:password|secret|token|api_key)", value["name"]) and bool(value.get("value"))}
                    leads.extend(lead(rule, path) for rule, matched in tests.items() if matched)
            elif PurePosixPath(path).name.lower() == "dockerfile":
                status = "limited_lexical"
                users = [line.split(maxsplit=1)[1].strip() for line in text.splitlines() if re.match(r"(?i)^\s*USER\s+", line)]
                if not users or users[-1].split(":")[0] in {"root", "0"}: leads.append(lead("root-user", path))
                for number, line in enumerate(text.splitlines(), 1):
                    if re.match(r"(?i)^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|API_KEY)\w*\s*=\s*\S+", line):
                        leads.append(lead("secret-config", path, number))
            elif path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
                status = "limited_lexical"
                for number, line in enumerate(text.splitlines(), 1):
                    if line.lstrip().startswith("#"): continue
                    if re.search(r"\bpermissions:\s*write-all\b", line): leads.append(lead("ci-write-all", path, number))
                    action = re.search(r"\buses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([^\s#]+)", line)
                    if action and not re.fullmatch(r"[0-9a-f]{40}", action[2]): leads.append(lead("ci-unpinned", path, number))
                    if re.search(r"\b(?:echo|printf|Write-Output)\b.*\$\{\{\s*secrets\.", line): leads.append(lead("ci-secret-output", path, number))
        except (ValueError, UnicodeError, TypeError, RecursionError):
            status = "inconclusive"
        files.append({"path": path, "sha256": sha256(raw), "status": status})
    unique = {row["id"]: row for row in leads}
    require(len(unique) <= 2048, "configuration leads exceed limit")
    return {"schema_version": 1, "adapter": "builtin-infrastructure", "files": files, "leads": list(unique.values()),
            "tool_version": None, "security_verdict": "not_established"}


def container_summary(container, image):
    require(container.get("Image") == image.get("Id") and isinstance(container.get("Config"), dict)
            and isinstance(container.get("HostConfig"), dict), "container/image observation differs")
    config, host = container["Config"], container["HostConfig"]
    rules = []
    if host.get("Privileged") is True: rules.append("privileged")
    if host.get("NetworkMode") == "host": rules.append("host-network")
    if str(config.get("User", "")).split(":")[0] in {"", "root", "0"}: rules.append("root-user")
    if any(m.get("Source") in {"/var/run/docker.sock", "/run/docker.sock"} for m in container.get("Mounts", [])): rules.append("docker-socket")
    if any(isinstance(e, str) and re.match(r"(?i)\w*(?:PASSWORD|SECRET|TOKEN|API_KEY)\w*=.+", e) for e in config.get("Env") or []): rules.append("secret-config")
    digests = image.get("RepoDigests") or []
    require(isinstance(digests, list) and len(digests) <= 32, "image digest inventory invalid")
    return {"container_id": container["Id"], "image_id": image["Id"],
            "repository_digests": sorted(set(d.rsplit("@", 1)[-1] for d in digests if isinstance(d, str) and re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", d))),
            "running": container.get("State", {}).get("Running") is True,
            "read_only_root": host.get("ReadonlyRootfs") is True,
            "leads": [lead(rule, "container") for rule in rules]}


def normalize_trivy(value, contents, tool_version):
    require(isinstance(value, dict) and value.get("SchemaVersion") == 2 and isinstance(value.get("Results", []), list), "unsupported Trivy output")
    leads, examined = [], set()
    for result in value.get("Results", []):
        require(isinstance(result, dict) and not result.get("Vulnerabilities"), "unconfigured scanner result")
        target = result.get("Target", "")
        require(isinstance(target, str), "invalid scanner path")
        path = target.removeprefix("/inputs/")
        relpath(path)
        require(path in contents, "scanner result outside selected input")
        examined.add(path)
        for field in ("Misconfigurations", "Secrets"):
            rows = result.get(field) or []
            require(isinstance(rows, list) and len(rows) <= 2048, "scanner findings exceed limit")
            for row in rows:
                require(isinstance(row, dict), "invalid scanner finding")
                rule = row.get("ID") if field == "Misconfigurations" else row.get("RuleID")
                require(isinstance(rule, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", rule), "invalid scanner rule")
                line = row.get("StartLine", row.get("CauseMetadata", {}).get("StartLine", 1))
                line = line if type(line) is int and 1 <= line <= 1048576 else 1
                leads.append({"id": "trivy-" + digest([path, rule, line])[:24], "rule": rule, "path": path, "line": line,
                    "title": "Potential embedded secret" if field == "Secrets" else "Configuration check requires review",
                    "fix": "Inspect the rule and exact location privately; verify context, permitted behavior and remediation before confirming.", "disposition": "needs_validation"})
    require(len(leads) <= 2048, "scanner lead inventory exceeds limit")
    return {"schema_version": 1, "adapter": "trivy-bundled", "tool_version": tool_version,
            "files": [{"path": p, "sha256": sha256(raw), "status": "reported" if p in examined else "no_reported_result"} for p, raw in sorted(contents.items())],
            "leads": leads, "security_verdict": "not_established"}
