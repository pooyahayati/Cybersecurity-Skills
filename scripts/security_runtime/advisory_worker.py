#!/usr/bin/env python3
"""One bounded official advisory acquisition. No target names or inherited auth."""

import os
from pathlib import Path
import re
import ssl
import sys
import threading
from urllib import request, error, parse as urls

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_runtime.common import fields, integer, parse, require
from security_runtime.sources import NoRedirect


def acquire(value):
    fields(value, {"action", "digest", "limit"})
    integer(value["limit"], 1, 256 * 1024**2)
    require(value["action"] in {"manifest", "blob"}, "unsupported advisory request")
    ref = value["digest"]
    require(ref is None and value["action"] == "manifest" or isinstance(ref, str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", ref), "invalid content digest")
    opener = request.build_opener(request.ProxyHandler({}), NoRedirect(), request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open("https://auth.docker.io/token?service=registry.docker.io&scope=repository:aquasec/trivy-db:pull", timeout=15) as response:
        token = parse(response.read(16385), 16384).get("token")
    require(isinstance(token, str) and len(token) <= 8192 and token.isascii()
            and not any(c.isspace() for c in token), "invalid registry token")
    endpoint = "https://registry-1.docker.io/v2/aquasec/trivy-db/" + ("manifests/" if value["action"] == "manifest" else "blobs/") + (ref or "2")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.oci.image.manifest.v1+json", "Cache-Control": "no-cache"}
    try:
        response = opener.open(request.Request(endpoint, headers=headers), timeout=20)
    except error.HTTPError as exc:
        location = exc.headers.get("Location", "")
        code = exc.code
        exc.close()
        parts = urls.urlsplit(location)
        require(value["action"] == "blob" and code in {302, 307}
                and parts.scheme == "https" and parts.hostname in {"production.cloudflare.docker.com", "production.cloudfront.docker.com"}
                and parts.port is None and not parts.username and not parts.password and not parts.fragment,
                "registry redirected outside official storage")
        response = opener.open(request.Request(location), timeout=20)  # Never forward registry authorization.
    with response:
        require(response.status == 200, "advisory unavailable")
        length = response.headers.get("Content-Length")
        require(length is None or length.isdecimal() and int(length) <= value["limit"], "oversized advisory response")
        data = response.read(value["limit"] + 1)
        require(len(data) <= value["limit"] and (length is None or len(data) == int(length)), "truncated or oversized advisory response")
        return data


if __name__ == "__main__":
    timer = threading.Timer(180, lambda: os._exit(124))
    timer.daemon = True
    timer.start()
    try:
        sys.stdout.buffer.write(acquire(parse(sys.stdin.buffer.read(4097), 4096)))
    except Exception:
        raise SystemExit(1)
    finally:
        timer.cancel()
