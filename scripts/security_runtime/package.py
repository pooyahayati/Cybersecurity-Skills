"""Exact-source skill archives. Verification never imports or runs package code."""

from __future__ import annotations

import io
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import warnings
import zipfile

from .common import Blocked, canonical, fields, parse, read_file, relpath, require, sha256
from .package_version import channel


NAME = "cybersecurity-skills"
MANIFEST = "PACKAGE.json"
ROOT_FILES = frozenset(("SKILL.md", "README.md", "AGENTS.md", "ROADMAP.md", "STATUS.md",
    "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md", "LICENSE"))
ROOT_DIRS = frozenset(("scripts", "references", "config", "agents", "docs", "templates"))
MAX_FILE = 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_FILES = 512


def hash_text(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value), "invalid SHA-256")
    return value


def directory(value):
    path = Path(value).absolute()
    require(path == path.resolve(strict=True) and path.is_dir(), "directory must be canonical and exist")
    for item in (path, *path.parents):
        info = item.lstat()
        require(not item.is_symlink() and not getattr(info, "st_file_attributes", 0) & 0x400,
                "linked directories are not permitted")
    return path


def selected(name):
    relpath(name)
    require(name.isascii(), "package paths must be portable ASCII")
    require(name in ROOT_FILES or name.split("/")[0] in ROOT_DIRS,
            "file is outside the distribution allowlist")
    require(all(not p.startswith(".") and p != "__pycache__" for p in name.split("/"))
            and not name.endswith((".pyc", ".pyo")), "generated/private package member")
    return name


def check_payload(files):
    require(isinstance(files, dict) and 1 <= len(files) <= MAX_FILES, "invalid package file count")
    names = set()
    for name, data in files.items():
        selected(name)
        require(isinstance(data, bytes) and len(data) <= MAX_FILE, "package member exceeds limit")
        folded = name.lower()
        require(folded not in names, "case-colliding package members")
        names.add(folded)
    for name in names:
        require(not any(parent in names for parent in ("/".join(name.split("/")[:i])
                    for i in range(1, len(name.split("/"))))), "file/directory package collision")
    require(sum(map(len, files.values())) <= MAX_TOTAL, "package exceeds expanded limit")
    require(ROOT_FILES <= files.keys() and {"agents/openai.yaml", "config/project.json",
            "config/head-source.json", "scripts/m1_control.py", "scripts/m2_assess.py",
            "scripts/m3_review.py", "scripts/m4_review.py", "scripts/m5_review.py"} <= files.keys(),
            "package is missing required skill content")
    project = parse(files["config/project.json"], MAX_FILE)
    require(isinstance(project, dict) and project.get("name") == NAME
            and type(project.get("schema_version")) is int and project["schema_version"] == 1
            and project.get("entrypoint") == "SKILL.md", "package has wrong skill identity")
    version = project.get("version")
    release_channel = channel(version)
    if release_channel != "development":
        require(project.get("maturity") == "bounded-qualification" and project.get("operational") is False,
                "release labels cannot declare general operational assessment readiness")
        require({"scripts/m6_package.py", "scripts/security_runtime/package_version.py",
                 "scripts/security_runtime/package_diagnostics.py", "docs/RELEASE-READINESS.md"} <= files.keys(),
                "release package is missing lifecycle/support content")
    skill = files["SKILL.md"].decode("utf-8")
    require(skill.startswith("---\n") and "\n---\n" in skill[4:], "missing skill frontmatter")
    header = skill.split("\n---\n", 1)[0]
    require(re.search(r"^name: " + NAME + "$", header, re.M)
            and re.search(r"^  version: " + re.escape(version) + "$", header, re.M),
            "package skill version/identity mismatch")
    source = parse(files["config/head-source.json"], MAX_FILE)
    require(isinstance(source, dict) and source.get("repository") == "pooyahayati/Cybersecurity-Skills"
            and isinstance(source.get("include"), list) and len(source["include"]) == len(ROOT_FILES | ROOT_DIRS)
            and set(source.get("include", [])) == ROOT_FILES | ROOT_DIRS,
            "head source and distribution selection differ")
    return version


def assemble(files, revision):
    """Encode reviewed bytes; the public builder obtains these from Git objects."""
    version = check_payload(files)
    require(isinstance(revision, str) and re.fullmatch(r"[a-f0-9]{40}", revision), "invalid source revision")
    manifest = {"format": "cybersecurity-skill-package", "schema_version": 1,
                "name": NAME, "version": version, "source_revision": revision,
                "files": {n: {"sha256": sha256(b), "size": len(b)} for n, b in sorted(files.items())}}
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted({**files, MANIFEST: canonical(manifest)}.items()):
            info = zipfile.ZipInfo(NAME + "/" + name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
    raw = output.getvalue()
    require(len(raw) <= MAX_ARCHIVE, "package archive exceeds limit")
    return raw


def verify(raw, expected_sha256):
    hash_text(expected_sha256)
    require(isinstance(raw, bytes) and len(raw) <= MAX_ARCHIVE and sha256(raw) == expected_sha256,
            "archive identity mismatch or size limit exceeded")
    files = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        require(1 <= len(members) <= MAX_FILES + 1, "invalid archive member count")
        names = set()
        for info in members:
            require(info.filename == info.orig_filename and info.filename.startswith(NAME + "/"), "wrong archive root/name")
            name = info.filename[len(NAME) + 1:]
            relpath(name)
            if name != MANIFEST:
                selected(name)
            require(name.lower() not in names and not info.is_dir(), "duplicate or directory archive member")
            names.add(name.lower())
            require(info.compress_type == zipfile.ZIP_STORED and not info.flag_bits & 1
                    and info.file_size == info.compress_size and 0 <= info.file_size <= MAX_FILE
                    and stat.S_IFMT(info.external_attr >> 16) == stat.S_IFREG,
                    "unsupported, linked or oversized archive member")
        for info in members:
            name = info.filename[len(NAME) + 1:]
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("error", UserWarning)
                    with archive.open(info) as stream:
                        data = stream.read(MAX_FILE + 1)
            except UserWarning as exc:
                raise Blocked("overlapping or ambiguous archive members") from exc
            require(len(data) == info.file_size, "truncated archive member")
            files[name] = data
    require(MANIFEST in files, "package manifest is missing")
    manifest = parse(files.pop(MANIFEST), MAX_FILE)
    fields(manifest, ("format", "schema_version", "name", "version", "source_revision", "files"))
    require(manifest["format"] == "cybersecurity-skill-package" and type(manifest["schema_version"]) is int
            and manifest["schema_version"] == 1 and manifest["name"] == NAME, "unsupported package manifest")
    require(isinstance(manifest["source_revision"], str)
            and re.fullmatch(r"[a-f0-9]{40}", manifest["source_revision"]), "invalid packaged revision")
    require(manifest["version"] == check_payload(files), "manifest version mismatch")
    require(isinstance(manifest["files"], dict) and set(manifest["files"]) == set(files),
            "manifest/member mismatch")
    for name, data in files.items():
        entry = manifest["files"][name]
        fields(entry, ("sha256", "size"))
        require(type(entry["size"]) is int and entry["size"] == len(data)
                and entry["sha256"] == sha256(data), "package member identity mismatch")
    return manifest, files


def read_archive(path, expected_sha256):
    path = Path(path).absolute()
    raw = read_file(directory(path.parent), path.name, MAX_ARCHIVE)
    manifest, files = verify(raw, expected_sha256)
    return raw, manifest, files


def write_new(path, data):
    path = Path(path)
    directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def build(root, revision, output):
    root = directory(root)
    require(isinstance(revision, str) and re.fullmatch(r"[a-f0-9]{40}", revision),
            "build requires the exact full Git commit")
    output = Path(output).absolute()
    directory(output.parent)
    require(not output.is_relative_to(root), "package output must stay outside source")
    require(not output.exists() and not output.is_symlink(), "output already exists; choose a new archive path")
    environment = {k: v for k, v in os.environ.items() if k.upper() in
                   ("SYSTEMROOT", "WINDIR", "PATH", "TMP", "TEMP")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    def git(*args):
        return subprocess.check_output(["git", "--no-replace-objects", "--no-lazy-fetch",
            "-c", "protocol.allow=never", "-c", "core.fsmonitor=false", "-C", str(root), *args],
            env=environment, stderr=subprocess.DEVNULL, timeout=30)
    def object_bytes(kind, oid):
        require(kind in ("commit", "tree", "blob") and re.fullmatch(r"[a-f0-9]{40}", oid),
                "unsupported Git object identity")
        size = int(git("cat-file", "-s", oid))
        require(0 <= size <= MAX_FILE, "Git object exceeds size limit")
        data = git("cat-file", kind, oid)
        # SHA-1 here verifies Git's object-address format, not publisher trust.
        header = kind.encode() + b" " + str(len(data)).encode() + b"\0"
        require(len(data) == size and hashlib.sha1(header + data, usedforsecurity=False).hexdigest() == oid,
                "Git object content identity mismatch")
        return data
    require(git("rev-parse", "--verify", revision + "^{commit}").decode().strip() == revision,
            "source revision is not an exact commit")
    commit = object_bytes("commit", revision)
    first = commit.split(b"\n", 1)[0]
    require(re.fullmatch(rb"tree [a-f0-9]{40}", first), "commit has no supported root tree")
    object_bytes("tree", first[5:].decode())
    tree = git("ls-tree", "-rtz", "--full-tree", revision)
    require(len(tree) <= MAX_TOTAL, "Git tree inventory exceeds limit")
    files = {}
    for row in tree.split(b"\0"):
        if not row:
            continue
        meta, raw_name = row.split(b"\t", 1)
        name = raw_name.decode("utf-8")
        mode, kind, oid = meta.split()
        if kind == b"tree":
            object_bytes("tree", oid.decode())
            continue
        if name not in ROOT_FILES and name.split("/")[0] not in ROOT_DIRS:
            continue
        selected(name)
        require(mode in (b"100644", b"100755") and kind == b"blob", "selected Git member is a link or submodule")
        require(len(files) < MAX_FILES, "too many selected Git members")
        data = object_bytes("blob", oid.decode())
        require(sum(map(len, files.values())) + len(data) <= MAX_TOTAL,
                "selected Git content exceeds limit")
        files[name] = data
    raw = assemble(files, revision)
    manifest, _ = verify(raw, sha256(raw))
    write_new(output, raw)
    return {"archive_sha256": sha256(raw), "bytes": len(raw), "manifest": manifest,
            "release_channel": channel(manifest["version"]),
            "source": "exact Git objects; worktree edits excluded", "freshness_verified": False,
            "publisher_authenticated": False, "security_verdict": "not_established", "stable_release": False}
