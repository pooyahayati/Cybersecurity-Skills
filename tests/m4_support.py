"""Owned local HTTP fixtures and explicit synthetic publisher provenance."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import time

from m2_support import ROOT, World
from runtime_support import Publisher, acceptance, source
from security_assessment.runtime import RuntimeReview
from security_runtime.common import read_file, sha256
from security_runtime.controller import Controller, HEAD_RESOURCES, selected_tree


class Server:
    def __init__(self, handler=None, tls_context=None):
        self.calls = []
        self.handler = handler or (lambda _path, _token: (200, {}, b"safe"))
        fixture = self

        class Request(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                fixture.calls.append({"path": self.path, "authorization": self.headers.get("Authorization"), "cookie": self.headers.get("Cookie")})
                status, headers, body = fixture.handler(self.path, self.headers.get("Authorization"))
                try:
                    self.send_response(status)
                    for key, value in headers.items(): self.send_header(key, value)
                    if "Content-Length" not in headers: self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionError): pass

            do_HEAD = do_GET

            def log_message(self, *_args): pass

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Request)
        self.http.daemon_threads = True
        if tls_context is not None: self.http.socket = tls_context.wrap_socket(self.http.socket, server_side=True)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.url = ("https" if tls_context is not None else "http") + "://127.0.0.1:" + str(self.http.server_port) + "/"

    def close(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(2)


class RuntimeWorld(World):
    def __init__(self, server, source_enabled=True, files=None, artifact=None):
        super().__init__(source=source_enabled)
        if files is not None:
            for name, raw in files.items():
                path = self.target / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            self.spec["source"]["files"] = sorted(files)
        self.spec["deployments"][0].update(id="local", environment="local", url=server.url, artifact=artifact or "sha256:" + "b" * 64)
        self.spec["model"]["actors"] += [{"id": "outsider", "kind": "user", "trust": "external"}, {"id": "tenant", "kind": "user", "trust": "external"}]
        self.publisher = Publisher()
        self.publisher.contents["head"] = {p: read_file(ROOT, p) for p in selected_tree(ROOT, HEAD_RESOURCES)}
        self.runtime = Controller(self.state, ROOT, self.publisher, clock=lambda: self.now[0])
        self.runtime.enroll(source("head", "head", HEAD_RESOURCES))
        candidate = self.runtime.prepare("head")["candidate"]
        self.runtime.review(acceptance(candidate))
        self.runtime.activate(candidate)
        self.control = RuntimeReview(self.state, ROOT, clock=lambda: self.now[0], upstream=self.publisher)
        self.server = server
        self.create()

    def route(self, name="read", path="", actor="visitor", kind="web", body=None, credential=None, identity=None, statuses=None, redirects=None):
        return {"id": name, "url": self.server.url + path, "method": "GET", "actor": actor, "credential": credential,
                "kind": kind, "identity": identity, "statuses": statuses or [200], "body_sha256": sha256(body) if body is not None else None,
                "redirects": [self.server.url + p for p in redirects or []]}

    def authorization(self, routes=None, name="web-audit", **limits):
        value = {"id": name, "deployment": "local", "network": "loopback", "addresses": ["127.0.0.1"], "ca_sha256": None,
                 "routes": routes or [self.route()], "limits": {"requests": 32, "seconds": 96, "body_bytes": 32768, "response_bytes": 1024, "timeout_seconds": 3, "expires_at": self.now[0] + 600}}
        value["limits"].update(limits)
        return value

    def authorize(self, value=None):
        value = value or self.authorization()
        self.control.web_authorize("demo", value)
        return value["id"]

    def execute(self, route="read", authorization="web-audit", credentials=None, ca=None):
        return self.control.web_execute("demo", authorization, route, credentials, ca)

    def scan_operation(self, adapter, output=None, docker=None, name="infra-run"):
        from m3_support import OutputDocker
        from security_runtime.common import canonical
        self.runtime.docker = docker or OutputDocker()
        if output is not None: self.runtime.docker.payload = canonical(output)
        if self.state.get("source", "m4") is None:
            self.publisher.contents["m4"] = {p: read_file(ROOT, p) for p in selected_tree(ROOT, ["scripts"])}
            self.runtime.enroll(source("m4", "tool", ["scripts"]))
        for component in ("runtime", "m4"):
            candidate = self.runtime.prepare(component)["candidate"]
            self.runtime.review(acceptance(candidate))
            self.runtime.activate(candidate)
        self.runtime.authorize({"id": name, "root": str(self.target), "inputs": self.spec["source"]["files"], "components": ["m4"], "network": "none",
            "operations": [{"id": "inspect", "component": "m4", "entrypoint": "scripts/m4_worker.py", "interpreter": "python", "arguments": [adapter], "timeout_seconds": 30, "max_output_bytes": 1024 * 1024}],
            "limits": {"calls": 1, "seconds": 30, "expires_at": self.now[0] + 600, "memory_mb": 256, "cpus": 0.5, "pids": 32, "tmpfs_mb": 16}})
        run = self.runtime.begin(name)["run"]
        return self.runtime.execute(run, "inspect")["operation"]

    def close(self):
        super().close()


def roles(vulnerable=False):
    def handler(path, token):
        identities = {"Bearer fixture-owner": b'{"user":"owner","tenant":"one"}',
                      "Bearer fixture-outsider": b'{"user":"outsider","tenant":"one"}',
                      "Bearer fixture-tenant": b'{"user":"tenant","tenant":"two"}'}
        if path == "/identity": return (200, {}, identities[token]) if token in identities else (401, {}, b"denied")
        if path == "/record": return (200, {}, b"synthetic-protected-record") if token == "Bearer fixture-owner" or vulnerable else (403, {}, b"denied")
        return 404, {}, b"missing"
    return handler


def role_plan(world):
    routes, credentials = [], {}
    for actor, identity in (("owner", b'{"user":"owner","tenant":"one"}'), ("outsider", b'{"user":"outsider","tenant":"one"}'), ("tenant", b'{"user":"tenant","tenant":"two"}')):
        credentials[actor] = {"header": "Authorization", "value": "Bearer fixture-" + actor}
        routes.append(world.route(actor + "-identity", "identity", actor, "identity", identity, actor))
        routes.append(world.route(actor + "-read", "record", actor, "resource", b"synthetic-protected-record" if actor == "owner" else b"denied", actor, actor + "-identity", [200] if actor == "owner" else [403]))
    routes.append(world.route("anonymous-read", "record", "visitor", "resource", b"denied", statuses=[403]))
    return world.authorization(routes), credentials


def compare_roles(world):
    spec, credentials = role_plan(world)
    world.authorize(spec)
    cases = []
    for actor in ("owner", "outsider", "tenant"):
        proof = world.execute(actor + "-identity", credentials=credentials)["operation"]
        record = world.execute(actor + "-read", credentials=credentials)["operation"]
        cases.append({"operation": record, "identity_operation": proof, "expectation": "allowed" if actor == "owner" else "denied"})
    record = world.execute("anonymous-read")["operation"]
    cases.append({"operation": record, "identity_operation": None, "expectation": "denied"})
    comparison = {"id": "roles", "deployment": "local", "policy_basis": "Synthetic record belongs to owner in tenant one; other actors must receive only the complete denial body.",
                  "identity_basis": "Exact identity JSON includes distinct synthetic user and tenant fields; these are observed assertions by the fixture service.", "cases": cases}
    return comparison, world.control.compare("demo", comparison)
