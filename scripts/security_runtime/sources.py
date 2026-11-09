"""Fail-closed public GitHub resolution and bounded acquisition."""

from __future__ import annotations

import gzip
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import os
from pathlib import Path
import re
import ssl
import sys
import tarfile
import time
from urllib import error, parse as urlparse, request
import zipfile

from .common import Blocked, canonical, fields, identifier, integer, parse, relpath, require, sha256, text, timestamp
from .process import bounded_process


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Http:
    """Killable acquisition worker bounds DNS, headers and trickled response bodies."""

    def __init__(self, token=None):
        self.token = token

    def get(self, url, limit=4 * 1024 * 1024, *, asset=False):
        integer(limit, 0, 512 * 1024 * 1024)
        require(self.token is None or isinstance(self.token, str) and len(self.token) <= 4096,
                "source token exceeds its limit")
        env = {"PATH": os.defpath}
        if os.name == "nt":
            for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
                if key in os.environ:
                    env[key] = os.environ[key]
        result = bounded_process([sys.executable, "-I", "-B", str(Path(__file__).with_name("http_worker.py"))],
            env, 120, limit + 4, input_data=canonical({"url": url, "limit": limit,
                                                      "asset": asset, "token": self.token}))
        require(result["exit_code"] == 0, "upstream unavailable; no cached success is usable")
        code, separator, body = result["content"].partition(b"\n")
        require(separator and code in (b"200", b"404"), "invalid acquisition worker response")
        return int(code), body


class Transport:
    def __init__(self, token=None):
        self.token = token

    def get(self, url, limit=4 * 1024 * 1024, *, asset=False):
        """No proxy/auth inheritance; one explicit asset-storage redirect only."""
        parts = urlparse.urlsplit(url)
        allowed = {"api.github.com", "raw.githubusercontent.com"}
        require(parts.scheme == "https" and parts.hostname in allowed and not parts.username
                and not parts.password and parts.port is None and not parts.fragment,
                "unsupported source URL")
        headers = {"User-Agent": "Cybersecurity-Skills-control", "Cache-Control": "no-cache"}
        if parts.hostname == "api.github.com":
            headers.update({"Accept": "application/octet-stream" if asset else "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2026-03-10"})
            if self.token:
                headers["Authorization"] = "Bearer " + self.token
        opener = request.build_opener(request.ProxyHandler({}), NoRedirect(),
                                       request.HTTPSHandler(context=ssl.create_default_context()))
        started = time.monotonic()
        try:
            try:
                response = opener.open(request.Request(url, headers=headers), timeout=20)
            except error.HTTPError as exc:
                exc.close()
                if asset and exc.code in (301, 302, 303, 307, 308):
                    destination = exc.headers.get("Location", "")
                    redirected = urlparse.urlsplit(destination)
                    require(redirected.scheme == "https"
                            and redirected.hostname == "release-assets.githubusercontent.com"
                            and redirected.port is None and not redirected.username
                            and not redirected.password and not redirected.fragment,
                            "asset redirect is outside trusted storage")
                    # Never forward the API token to the storage host.
                    response = opener.open(request.Request(destination, headers={
                        "User-Agent": headers["User-Agent"]}), timeout=20)
                elif exc.code == 404:
                    return 404, b""
                else:
                    raise Blocked("upstream request failed or redirected") from None
            with response:
                require(response.status == 200, "unexpected upstream response")
                length = response.headers.get("Content-Length")
                if length is not None:
                    require(length.isdecimal() and int(length) <= limit, "upstream response exceeds its limit")
                output = bytearray()
                while True:
                    require(time.monotonic() - started <= 120, "upstream transfer deadline exceeded")
                    chunk = response.read1(min(65536, limit + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                    require(len(output) <= limit, "upstream response exceeds its limit")
                return 200, bytes(output)
        except Blocked:
            raise
        except (OSError, ValueError, error.URLError, TimeoutError) as exc:
            raise Blocked("upstream unavailable; no cached success is usable") from exc


def source_spec(value):
    if isinstance(value, dict) and value.get("provider") == "trivy-db-oci":
        from .advisory import source_spec as advisory_spec
        return advisory_spec(value)
    fields(value, {"id", "kind", "repository", "repository_id", "owner_id", "include",
                   "asset", "max_download_bytes", "max_unpacked_bytes", "data_max_age_seconds"})
    identifier(value["id"])
    require(value["kind"] in ("head", "skill", "tool", "data"), "unsupported component kind")
    require(isinstance(value["repository"], str) and len(value["repository"]) <= 141 and re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", value["repository"]),
        "repository must be a canonical owner/name")
    integer(value["repository_id"], 1, 2**63 - 1)
    integer(value["owner_id"], 1, 2**63 - 1)
    integer(value["max_download_bytes"], 1, 512 * 1024 * 1024)
    integer(value["max_unpacked_bytes"], 1, 512 * 1024 * 1024)
    include, asset = value["include"], value["asset"]
    require(isinstance(include, list) and len(include) <= 64
            and all(isinstance(p, str) for p in include), "invalid resource selection")
    for path in include:
        relpath(path)
    require(len(set(include)) == len(include), "duplicate resource selection")
    require(bool(include) != (asset is not None), "select repository files or one release asset")
    if asset is not None:
        fields(asset, {"name", "format", "members"})
        name = text(asset["name"], 256)
        require(re.fullmatch(r"[A-Za-z0-9_.{}-]+", name)
                and name.count("{version}") <= 1
                and "{" not in name.replace("{version}", "")
                and "}" not in name.replace("{version}", ""), "invalid asset name template")
        require(asset["format"] in ("raw", "zip", "tar.gz"), "unsupported asset archive")
        require(isinstance(asset["members"], list) and 1 <= len(asset["members"]) <= 64,
                "asset needs explicit member paths")
        for path in asset["members"]:
            relpath(path)
            require(path.count("{version}") <= 1 and "{" not in path.replace("{version}", "")
                    and "}" not in path.replace("{version}", ""), "invalid member template")
        require(len(set(asset["members"])) == len(asset["members"]), "duplicate asset members")
        require(asset["format"] != "raw" or len(asset["members"]) == 1,
                "raw assets need one output member")
    if value["kind"] == "data":
        integer(value["data_max_age_seconds"], 1, 31 * 86400)
    else:
        require(value["data_max_age_seconds"] is None, "data age policy belongs to data components")
    require(value["kind"] not in ("head", "skill") or (bool(include) and asset is None),
            "instruction components require repository files")
    return value


class GitHub:
    def __init__(self, http=None, clock=time.time):
        self.http, self.clock = http or Http(), clock

    def json(self, suffix, allow_missing=False):
        status, body = self.http.get("https://api.github.com/repos/" + suffix)
        if status == 404 and allow_missing:
            return None
        require(status == 200, "required upstream metadata is unavailable")
        return parse(body, 16 * 1024 * 1024)

    def resolve(self, spec):
        spec = source_spec(spec)
        if spec.get("provider") == "trivy-db-oci":
            from .advisory import Advisory
            return Advisory(clock=self.clock).resolve(spec)
        repo = spec["repository"]
        metadata = self.json(repo)
        require(isinstance(metadata, dict) and type(metadata.get("id")) is int
                and metadata.get("id") == spec["repository_id"]
                and isinstance(metadata.get("owner"), dict)
                and type(metadata["owner"].get("id")) is int
                and metadata["owner"].get("id") == spec["owner_id"]
                and isinstance(metadata.get("full_name"), str)
                and metadata["full_name"].casefold() == repo.casefold()
                and metadata.get("private") is False and metadata.get("archived") is False
                and metadata.get("disabled", False) is False,
                "publisher identity changed or repository is unavailable/unsupported")
        release = self.json(repo + "/releases/latest", allow_missing=True)
        if release is None:
            # A 404 alone cannot justify falling back to a branch.
            exhausted = False
            for page in range(1, 11):
                rows = self.json(repo + f"/releases?per_page=100&page={page}")
                require(isinstance(rows, list), "invalid release listing")
                for row in rows:
                    require(isinstance(row, dict) and type(row.get("draft")) is bool
                            and type(row.get("prerelease")) is bool, "invalid release record")
                    require(row["draft"] or row["prerelease"],
                            "latest-release metadata contradicts the stable release listing")
                if len(rows) < 100:
                    exhausted = True
                    break
            require(exhausted, "cannot establish absence of stable releases")
            require(spec["asset"] is None, "release asset requires a stable release")
            branch = text(metadata.get("default_branch"), 256)
            commit = self.commit_at_ref(repo, "heads/" + urlparse.quote(branch, safe=""))
            channel, label, published, release_id = "default-branch", branch, None, None
        else:
            require(isinstance(release, dict) and release.get("draft") is False
                    and release.get("prerelease") is False, "latest release is not stable")
            release_id = integer(release.get("id"), 1, 2**63 - 1)
            label = text(release.get("tag_name"), 256)
            published = timestamp(release.get("published_at"))
            # Resolve the tag itself, not the mutable target_commitish branch.
            commit = self.commit_at_ref(repo, "tags/" + urlparse.quote(label, safe=""))
            channel = "stable-release"
        require(isinstance(commit, dict) and re.fullmatch(r"[0-9a-f]{40}", str(commit.get("sha"))),
                "invalid resolved commit")
        details = commit.get("commit", {})
        require(isinstance(details, dict) and isinstance(details.get("tree"), dict)
                and isinstance(details.get("committer"), dict), "invalid commit metadata")
        tree = details.get("tree", {}).get("sha")
        require(re.fullmatch(r"[0-9a-f]{40}", str(tree)), "invalid commit tree")
        if published is None:
            published = timestamp(details.get("committer", {}).get("date"))
        now = self.clock()
        require(published <= now + 300, "upstream timestamp is in the future")
        if spec["kind"] == "data":
            require(now - published <= spec["data_max_age_seconds"], "data component is too old")
        identity = {"repository": repo, "repository_id": metadata["id"],
                    "owner_id": metadata["owner"]["id"], "channel": channel,
                    "label": label, "revision": commit["sha"], "tree": tree,
                    "release_id": release_id, "published_at": published}
        verification = details.get("verification", {})
        require(isinstance(verification, dict), "invalid commit verification metadata")
        provenance = {"git_signature_verified": verification.get("verified") is True,
                      "git_signature_reason": str(verification.get("reason", "unavailable"))[:128],
                      "basis": "official HTTPS API and enrolled repository/owner identity"}
        if spec["asset"] is not None:
            version = label[1:] if label.startswith("v") else label
            require(re.fullmatch(r"[A-Za-z0-9_.-]+", version), "unsupported release version label")
            name = spec["asset"]["name"].replace("{version}", version)
            assets = release.get("assets")
            require(isinstance(assets, list), "release assets are unavailable")
            matches = [a for a in assets if isinstance(a, dict) and a.get("name") == name]
            require(len(matches) == 1, "release asset is absent or ambiguous")
            asset = matches[0]
            integer(asset.get("id"), 1, 2**63 - 1)
            integer(asset.get("size"), 1, spec["max_download_bytes"])
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", str(asset.get("digest"))),
                    "release asset lacks an official SHA-256 digest")
            identity["asset"] = {"id": asset["id"], "name": name,
                                 "sha256": asset["digest"][7:], "size": asset["size"]}
            provenance["asset_signature_verified"] = False
        return {"identity": identity, "provenance": provenance, "checked_at": now}

    def commit_at_ref(self, repo, ref):
        response = self.json(repo + "/git/ref/" + ref)
        require(isinstance(response, dict), "invalid Git reference")
        obj = response.get("object")
        seen = set()
        for _ in range(8):
            require(isinstance(obj, dict) and re.fullmatch(r"[0-9a-f]{40}", str(obj.get("sha")))
                    and obj["sha"] not in seen, "invalid or cyclic Git reference")
            seen.add(obj["sha"])
            if obj.get("type") == "commit":
                result = self.json(repo + "/commits/" + obj["sha"])
                require(isinstance(result, dict) and result.get("sha") == obj["sha"],
                        "resolved commit does not match the Git reference")
                return result
            require(obj.get("type") == "tag", "Git reference does not identify a commit")
            response = self.json(repo + "/git/tags/" + obj["sha"])
            require(isinstance(response, dict), "invalid annotated tag")
            obj = response.get("object")
        raise Blocked("Git reference nesting exceeds its limit")

    def fetch(self, spec, resolved):
        if spec.get("provider") == "trivy-db-oci":
            from .advisory import Advisory
            return Advisory(clock=self.clock).fetch(spec, resolved)
        identity = resolved["identity"]
        if spec["asset"] is not None:
            asset = identity["asset"]
            status, content = self.http.get("https://api.github.com/repos/" + spec["repository"]
                + "/releases/assets/" + str(asset["id"]), asset["size"], asset=True)
            require(status == 200 and len(content) == asset["size"]
                    and sha256(content) == asset["sha256"], "release asset integrity check failed")
            return unpack(content, spec["asset"], spec["max_unpacked_bytes"], identity["label"].removeprefix("v"))
        tree = self.json(spec["repository"] + "/git/trees/" + identity["tree"] + "?recursive=1")
        require(isinstance(tree, dict) and tree.get("truncated") is False
                and isinstance(tree.get("tree"), list), "repository tree is incomplete")
        selected = []
        aliases = set()
        total = 0
        for item in tree["tree"]:
            require(isinstance(item, dict) and isinstance(item.get("path"), str), "invalid tree entry")
            path = item["path"]
            if not any(path == prefix or path.startswith(prefix + "/") for prefix in spec["include"]):
                continue
            relpath(path)
            require(path.casefold() not in aliases, "case-colliding upstream paths")
            aliases.add(path.casefold())
            if item.get("type") == "tree":
                continue
            require(item.get("type") == "blob" and item.get("mode") in ("100644", "100755")
                    and re.fullmatch(r"[0-9a-f]{40}", str(item.get("sha"))),
                    "unsupported source link, submodule or object")
            total += integer(item.get("size"), 0, spec["max_unpacked_bytes"])
            require(total <= min(spec["max_download_bytes"], spec["max_unpacked_bytes"])
                    and len(selected) < 256, "selected source exceeds its limits")
            selected.append(item)
        require(selected and all(any(i["path"] == p or i["path"].startswith(p + "/")
                                     for i in selected) for p in spec["include"]),
                "selected resources are missing")

        def fetch_one(item):
            url = "https://raw.githubusercontent.com/" + spec["repository"] + "/" + identity["revision"]
            url += "/" + urlparse.quote(item["path"], safe="/")
            status, content = self.http.get(url, item["size"])
            git_hash = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\x00" + content).hexdigest()
            require(status == 200 and len(content) == item["size"] and git_hash == item["sha"],
                    "source file does not match the resolved Git object")
            return item["path"], content

        with ThreadPoolExecutor(max_workers=4) as pool:
            return dict(pool.map(fetch_one, selected))


def unpack(content, selection, maximum, version=None):
    if any("{version}" in p for p in selection["members"]):
        require(isinstance(version, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}", version), "safe resolved release version required")
    wanted = [p.replace("{version}", version or "") for p in selection["members"]]
    for path in wanted: relpath(path)
    require(len({p.casefold() for p in wanted}) == len(wanted), "resolved member paths collide")
    if selection["format"] == "raw":
        require(len(content) <= maximum, "raw asset exceeds unpacked limit")
        return {wanted[0]: content}
    result, seen, total = {}, set(), 0
    try:
        if selection["format"] == "zip":
            archive = zipfile.ZipFile(io.BytesIO(content))
        else:
            # Bound decompression before tarfile processes extended headers or sparse metadata.
            expanded_limit = maximum + 4096 * 1024
            with gzip.GzipFile(fileobj=io.BytesIO(content)) as compressed:
                expanded = compressed.read(expanded_limit + 1)
            require(len(expanded) <= expanded_limit, "tar stream exceeds its expanded limit")
            archive = tarfile.open(fileobj=io.BytesIO(expanded), mode="r:")
        with archive:
            members = archive.infolist() if isinstance(archive, zipfile.ZipFile) else archive
            for index, member in enumerate(members):
                require(index < 4096, "archive member count exceeds limit")
                name = member.filename if isinstance(archive, zipfile.ZipFile) else member.name
                name = name.rstrip("/")
                relpath(name)
                require(name.casefold() not in seen, "archive contains duplicate or colliding paths")
                seen.add(name.casefold())
                if isinstance(archive, zipfile.ZipFile):
                    mode = member.external_attr >> 16
                    require((mode & 0o170000) in (0, 0o100000, 0o040000), "archive contains a special file")
                    size, directory = member.file_size, member.is_dir()
                else:
                    require((member.isfile() or member.isdir()) and not member.sparse,
                            "archive contains a link, sparse or special file")
                    size, directory = member.size, member.isdir()
                total += size
                require(total <= maximum and size >= 0, "archive exceeds unpacked limit")
                if name in wanted:
                    require(not directory, "selected archive member is not a file")
                    stream = archive.open(member) if isinstance(archive, zipfile.ZipFile) else archive.extractfile(member)
                    with stream:
                        value = stream.read(size + 1)
                    require(len(value) == size, "archive member size mismatch")
                    result[name] = value
    except Exception as exc:
        if isinstance(exc, Blocked):
            raise
        raise Blocked("invalid or unsupported archive") from exc
    require(set(result) == set(wanted), "required archive members are missing")
    return result
