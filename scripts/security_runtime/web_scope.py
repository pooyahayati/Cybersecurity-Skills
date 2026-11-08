"""Exact M4 read authority. A passive URL or a response never grants permission."""

import ipaddress
import re
from urllib.parse import unquote, urlsplit, urlunsplit

from .common import fields, identifier, integer, number, require, text


def url(value):
    text(value, 2048)
    require(value.isascii() and not any(c.isspace() or ord(c) < 32 for c in value)
            and "\\" not in value, "invalid request URL")
    parts = urlsplit(value)
    require(parts.scheme in {"http", "https"} and parts.hostname and not parts.username
            and not parts.password and not parts.query and not parts.fragment, "unsupported request URL")
    host = parts.hostname
    require(host == host.lower() and re.fullmatch(r"[a-z0-9.:-]+", host), "noncanonical host")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    integer(port, 1, 65535)
    path = parts.path or "/"
    decoded = unquote(path)
    require(path.startswith("/") and not path.startswith("//") and "\\" not in decoded
            and not any(ord(c) < 32 for c in decoded) and not any(p in {".", ".."} for p in decoded.split("/"))
            and not re.search(r"%(?:2f|5c|25)", path, re.I), "ambiguous request path")
    authority = ("[" + host + "]" if ":" in host else host)
    if parts.port is not None: authority += ":" + str(port)
    require(value == urlunsplit((parts.scheme, authority, path, "", "")), "URL must be canonical")
    return parts.scheme, host, port, path


def address(value, network):
    text(value, 64)
    ip = ipaddress.ip_address(value)
    require(str(ip) == value and "%" not in value and not getattr(ip, "ipv4_mapped", None), "noncanonical destination")
    require(not (ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved and not ip.is_loopback), "reserved destination")
    private = any(ip in net for net in (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16")) if ip.version == net.version) if ip.version == 4 else ip in ipaddress.ip_network("fc00::/7")
    require((network == "public" and ip.is_global) or (network == "private" and private)
            or (network == "loopback" and ip.is_loopback), "destination is outside its declared network class")
    return ip


def fingerprint(value, nullable=False):
    require(nullable and value is None or isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "SHA-256 required")


def authority(value, deployment, actors, now):
    fields(value, {"id", "deployment", "network", "addresses", "routes", "limits", "ca_sha256"})
    identifier(value["id"])
    require(value["deployment"] == deployment["id"], "deployment differs")
    require(value["network"] in {"public", "private", "loopback"}, "unsupported network class")
    require(value["network"] != "loopback" or deployment["environment"] == "local", "loopback requires local environment")
    origin = url(deployment["url"])
    require(origin[0] == "https" or value["network"] == "loopback", "TLS is required outside local loopback")
    addresses = value["addresses"]
    require(isinstance(addresses, list) and 0 < len(addresses) <= 8 and len(set(addresses)) == len(addresses), "invalid address pins")
    for item in addresses: address(item, value["network"])
    fingerprint(value["ca_sha256"], nullable=True)
    limits = value["limits"]
    fields(limits, {"requests", "seconds", "body_bytes", "response_bytes", "timeout_seconds", "expires_at"})
    integer(limits["requests"], 1, 100)
    integer(limits["seconds"], 1, 600)
    integer(limits["body_bytes"], 1, 8 * 1024 * 1024)
    integer(limits["response_bytes"], 1, min(262144, limits["body_bytes"]))
    integer(limits["timeout_seconds"], 1, min(15, limits["seconds"]))
    number(limits["expires_at"], now + 1, now + 3600)
    require(isinstance(value["routes"], list) and 0 < len(value["routes"]) <= 32, "invalid routes")
    routes = {}
    for row in value["routes"]:
        fields(row, {"id", "url", "method", "actor", "credential", "kind", "identity", "statuses", "body_sha256", "redirects"})
        identifier(row["id"])
        require(row["id"] not in routes, "duplicate route")
        require(row["actor"] in actors and row["method"] in {"GET", "HEAD"}, "unsupported actor or method")
        require(row["kind"] in {"identity", "resource", "web"}, "unsupported observation kind")
        if row["credential"] is not None: identifier(row["credential"])
        if row["identity"] is not None: identifier(row["identity"])
        require(isinstance(row["statuses"], list) and 0 < len(row["statuses"]) <= 5, "expected status required")
        for status in row["statuses"]: integer(status, 200, 599)
        fingerprint(row["body_sha256"], nullable=True)
        if row["kind"] in {"identity", "resource"}:
            require(row["method"] == "GET" and row["body_sha256"] is not None, "identity/resource requires a complete body predicate")
        if row["kind"] == "identity":
            require(row["identity"] is None and row["credential"] is not None and row["statuses"] == [200], "invalid identity predicate")
        require(isinstance(row["redirects"], list) and len(row["redirects"]) <= 4, "redirect chain exceeds limit")
        for destination in [row["url"], *row["redirects"]]:
            target = url(destination)
            require(target[:3] == origin[:3], "redirect or route leaves the deployment origin")
            require(origin[3] == "/" or target[3] == origin[3] or target[3].startswith(origin[3].rstrip("/") + "/"), "route leaves deployment path")
        require(len(set([row["url"], *row["redirects"]])) == 1 + len(row["redirects"]), "redirect cycle")
        routes[row["id"]] = row
    for row in routes.values():
        actor = actors[row["actor"]]
        if actor["kind"] == "anonymous":
            require(row["credential"] is None and row["identity"] is None, "anonymous route cannot carry credentials")
        elif row["kind"] == "resource":
            proof = routes.get(row["identity"])
            require(proof and proof["kind"] == "identity" and proof["actor"] == row["actor"]
                    and proof["credential"] == row["credential"], "resource needs the same actor/credential identity predicate")


def credential(value):
    fields(value, {"header", "value"})
    require(value["header"] in {"Authorization", "Cookie"}, "unsupported credential header")
    text(value["value"], 2048)
    require(value["value"].isascii() and all(32 <= ord(c) < 127 for c in value["value"]), "invalid credential value")
