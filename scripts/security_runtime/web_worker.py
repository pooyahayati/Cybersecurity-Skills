#!/usr/bin/env python3
"""One pinned socket, one request, no redirect, proxy, cookie jar or target code."""

import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_runtime.common import fields, integer, parse, require, sha256
from security_runtime.web_scope import address, credential, url


def collect(value):
    fields(value, {"url", "method", "addresses", "network", "timeout", "limit", "credential", "ca"})
    scheme, host, port, path = url(value["url"])
    integer(value["timeout"], 1, 15)
    integer(value["limit"], 1, 262144)
    require(value["method"] in {"GET", "HEAD"}, "unsupported method")
    pins = {str(address(item, value["network"])) for item in value["addresses"]}
    require(0 < len(pins) <= 8 and (scheme == "https" or value["network"] == "loopback"), "unsupported destination")
    if value["credential"] is not None: credential(value["credential"])
    try:
        resolved = {str(ipaddress.ip_address(host))}
    except ValueError:
        resolved = {str(ipaddress.ip_address(row[4][0])) for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    require(resolved and resolved <= pins, "DNS differs from authorized pins")
    for item in resolved: address(item, value["network"])
    # Connect directly to one validated literal. Never ask DNS again, retry, or use a proxy.
    selected = sorted(resolved)[0]
    sock = socket.socket(socket.AF_INET6 if ":" in selected else socket.AF_INET, socket.SOCK_STREAM)
    connection = None
    try:
        sock.settimeout(value["timeout"])
        sock.connect((selected, port))
        tls = None
        if scheme == "https":
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            if value["ca"] is not None:
                require(isinstance(value["ca"], str) and len(value["ca"]) <= 4096, "CA exceeds limit")
                context.load_verify_locations(cadata=value["ca"])
            sock = context.wrap_socket(sock, server_hostname=host)
            tls = {"version": sock.version(), "peer_certificate_sha256": sha256(sock.getpeercert(binary_form=True))}
        http.client._MAXLINE = 8192
        http.client._MAXHEADERS = 32
        connection = http.client.HTTPConnection(host, port, timeout=value["timeout"])
        connection.sock = sock
        headers = {"User-Agent": "Cybersecurity-Skills-M4", "Accept-Encoding": "identity", "Connection": "close"}
        if value["credential"] is not None: headers[value["credential"]["header"]] = value["credential"]["value"]
        connection.request(value["method"], path, headers=headers)
        response = connection.getresponse()
        pairs = response.getheaders()
        require(sum(len(k) + len(v) for k, v in pairs) <= 32768, "response headers exceed limit")
        lengths = response.headers.get_all("Content-Length", [])
        require(len(lengths) <= 1 and (not lengths or lengths[0].isdecimal() and (value["method"] == "HEAD" or int(lengths[0]) <= value["limit"])), "invalid or oversized content length")
        require(not (lengths and response.getheader("Transfer-Encoding")), "ambiguous response framing")
        require(response.getheader("Content-Encoding", "identity").lower() == "identity", "compressed response unsupported")
        body = response.read(value["limit"] + 1)
        require(len(body) <= value["limit"], "response body exceeds limit")
        if lengths and value["method"] != "HEAD": require(len(body) == int(lengths[0]), "incomplete body")
        locations = response.headers.get_all("Location", [])
        require(len(locations) <= 1, "ambiguous redirect")
        cookies = response.headers.get_all("Set-Cookie", [])
        flags = {"hsts": bool(response.getheader("Strict-Transport-Security")),
                 "csp": bool(response.getheader("Content-Security-Policy")),
                 "nosniff": response.getheader("X-Content-Type-Options", "").lower() == "nosniff",
                 "cookie_without_secure": any("secure" not in {p.strip().split("=", 1)[0].lower() for p in c.split(";")[1:]} for c in cookies),
                 "cookie_without_httponly": any("httponly" not in {p.strip().split("=", 1)[0].lower() for p in c.split(";")[1:]} for c in cookies)}
        return {"schema_version": 1, "status": response.status, "body_bytes": len(body), "body_sha256": sha256(body),
                "location": locations[0] if locations else None, "address": selected, "tls": tls, "headers": flags}
    finally:
        if connection is not None: connection.close()
        sock.close()


if __name__ == "__main__":
    timer = None
    try:
        value = parse(sys.stdin.buffer.read(8193), 8192)
        integer(value["timeout"], 1, 15)
        # Remains bounded even if the controlling process dies during DNS or a
        # trickled response. This worker creates no subprocesses or retries.
        timer = threading.Timer(value["timeout"], lambda: os._exit(124))
        timer.daemon = True
        timer.start()
        result = collect(value)
        print(json.dumps(result, allow_nan=False))
    except Exception:
        print('{"status":"unavailable"}')
        raise SystemExit(1)
    finally:
        if timer is not None: timer.cancel()
