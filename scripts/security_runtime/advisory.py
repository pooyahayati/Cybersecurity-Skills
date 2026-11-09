"""Explicit official OCI advisory source; never a GitHub-release fallback."""

import os
import gzip
import io
import tarfile
import secrets
from pathlib import Path
import re
import sys
import time

from .common import canonical, fields, integer, parse, portable_tree, require, sha256, timestamp
from .process import bounded_process

FEED = "registry-1.docker.io/aquasec/trivy-db:2"


def source_spec(value):
    fields(value, {"id", "kind", "provider", "feed", "max_download_bytes",
                   "max_unpacked_bytes", "data_max_age_seconds"})
    require(value["id"] == "trivy-db" and value["kind"] == "data"
            and value["provider"] == "trivy-db-oci" and value["feed"] == FEED,
            "unsupported official advisory feed")
    integer(value["max_download_bytes"], 1, 256 * 1024**2)
    integer(value["max_unpacked_bytes"], 1, 4 * 1024**3)
    integer(value["data_max_age_seconds"], 1, 86400)
    return value


def validate_manifest(raw, spec, now):
    value = parse(raw, 65536)
    require(value.get("schemaVersion") == 2 and value.get("mediaType") == "application/vnd.oci.image.manifest.v1+json"
            and value.get("artifactType") == "application/vnd.aquasec.trivy.config.v1+json", "unsupported advisory artifact")
    layers = value.get("layers")
    require(isinstance(layers, list) and len(layers) == 1, "advisory data is incomplete or ambiguous")
    layer = layers[0]
    require(layer.get("mediaType") == "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"
            and re.fullmatch(r"sha256:[0-9a-f]{64}", str(layer.get("digest")))
            and layer.get("annotations", {}).get("org.opencontainers.image.title") == "db.tar.gz", "unsupported advisory layer")
    integer(layer.get("size"), 1, spec["max_download_bytes"])
    published = timestamp(value.get("annotations", {}).get("org.opencontainers.image.created"))
    require(now - spec["data_max_age_seconds"] <= published <= now + 300, "advisory publication is stale or in the future")
    return {"provider": "trivy-db-oci", "feed": FEED, "revision": "sha256:" + sha256(raw),
            "published_at": published, "layer": {k: layer[k] for k in ("digest", "size")}}


def validate_metadata(raw, spec, now, published):
    data = parse(raw, 16384)
    require(data.get("Version") == 2, "unsupported advisory database schema")
    updated = timestamp(data.get("UpdatedAt"))
    next_update = timestamp(data.get("NextUpdate"))
    require(now - spec["data_max_age_seconds"] <= updated <= published + 300
            and updated <= now + 300 and updated < next_update and now < next_update,
            "advisory database is stale or inconsistent")
    return data


class Advisory:
    def __init__(self, clock=time.time, transport=None):
        self.clock, self.transport = clock, transport

    def get(self, action, digest=None, limit=65536):
        if self.transport is not None:
            return self.transport(action, digest, limit)
        env = {"PATH": os.defpath}
        if os.name == "nt":
            for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
                if key in os.environ: env[key] = os.environ[key]
        result = bounded_process([sys.executable, "-I", "-B", str(Path(__file__).with_name("advisory_worker.py"))],
            env, 180, limit, input_data=canonical({"action": action, "digest": digest, "limit": limit}))
        require(result["exit_code"] == 0, "official advisory feed unavailable; cached success is unusable")
        return result["content"]

    def resolve(self, spec):
        source_spec(spec)
        identity = validate_manifest(self.get("manifest"), spec, self.clock())
        return {"identity": identity, "checked_at": self.clock(), "provenance": {
            "basis": "Explicit official Docker Hub repository over HTTPS; OCI content digests",
            "signature_verified": False, "private_package_disclosure": False}}

    def fetch(self, spec, resolved):
        identity = resolved["identity"]
        raw = self.get("manifest", identity["revision"])
        require(validate_manifest(raw, spec, self.clock()) == identity, "advisory manifest changed")
        layer = identity["layer"]
        content = self.get("blob", layer["digest"], layer["size"])
        require(len(content) == layer["size"] and "sha256:" + sha256(content) == layer["digest"], "advisory data integrity failed")
        return {"db.tar.gz": content}


def stage_database(parent, files, spec, resolved, now):
    """Stream the official large Bolt database; no extraction of arbitrary paths."""
    require(set(files) == {"db.tar.gz"}, "unexpected advisory payload")
    stage = parent / ('stage-' + secrets.token_hex(16))
    stage.mkdir(mode=0o700)
    (stage / 'db').mkdir(mode=0o700)
    seen, total = set(), 0
    class Limited:
        def __init__(self, stream): self.stream, self.count = stream, 0
        def read(self, size):
            require(0 <= size <= 1024 * 1024, "unbounded archive read")
            data = self.stream.read(size)
            self.count += len(data)
            require(self.count <= spec['max_unpacked_bytes'] + 1024 * 1024, "expanded advisory exceeds limit")
            return data
    with gzip.GzipFile(fileobj=io.BytesIO(files['db.tar.gz'])) as compressed:
        limited = Limited(compressed)
        with tarfile.open(fileobj=limited, mode='r|') as archive:
            for member in archive:
                require(member.name in {'trivy.db', 'metadata.json'} and member.name not in seen
                        and member.isfile() and not member.sparse and not member.pax_headers,
                        "unexpected, duplicate or special advisory member")
                seen.add(member.name)
                total += member.size
                require(0 < member.size and total <= spec['max_unpacked_bytes'], "advisory exceeds unpacked limit")
                require(member.name != 'metadata.json' or member.size <= 16384, "oversized advisory metadata")
                with archive.extractfile(member) as source, (stage/'db'/member.name).open('xb') as target:
                    remaining = member.size
                    while remaining:
                        chunk = source.read(min(1024*1024, remaining))
                        require(chunk, "truncated advisory member")
                        target.write(chunk)
                        remaining -= len(chunk)
                    target.flush()
                    os.fsync(target.fileno())
        while True:
            tail = limited.read(65536)
            if not tail: break
            require(not tail.strip(b'\0'), "unexpected trailing advisory data")
    require(seen == {'trivy.db', 'metadata.json'}, "incomplete advisory database")
    validate_metadata((stage/'db/metadata.json').read_bytes(), spec, now, resolved['identity']['published_at'])
    manifest = portable_tree(stage, limit=spec['max_unpacked_bytes'])
    if os.name != 'nt':
        for path in (stage/'db/trivy.db', stage/'db/metadata.json', stage/'db'): path.chmod(0o555)
    return stage, manifest
