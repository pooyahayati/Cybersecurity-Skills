"""Closed M5 workload contracts; rates are admission ceilings, never VU counts."""

from .common import fields, identifier, integer, number, require, text
from .web_scope import authority, fingerprint


def workload(value, case, now):
    fields(value, {"id", "web", "scenario", "purpose", "workload", "dataset", "phases", "abort", "acceptance"})
    identifier(value["id"])
    for key in ("purpose", "workload", "dataset"): text(value[key], 1024)
    deployment = next((d for d in case["scope"]["deployments"] if d["id"] == value["web"].get("deployment")), None)
    require(deployment is not None, "deployment unavailable")
    authority(value["web"], deployment, {a["id"]: a for a in case["scope"]["model"]["actors"]}, now)
    require(value["scenario"] in {"baseline", "load", "stress", "spike", "soak", "breakpoint"}, "unsupported scenario")
    routes = value["web"]["routes"]
    require(len(routes) == 1 and routes[0]["kind"] == "web" and not routes[0]["redirects"]
            and routes[0]["body_sha256"] is not None and routes[0]["statuses"] == [200], "one exact successful read with complete body predicate required")
    require(isinstance(value["phases"], list) and 1 <= len(value["phases"]) <= 6, "invalid phases")
    requests, seconds, names = 0, 0, set()
    for phase in value["phases"]:
        fields(phase, {"id", "requests", "concurrency", "rps", "seconds"})
        identifier(phase["id"])
        require(phase["id"] not in names, "duplicate phase")
        names.add(phase["id"])
        integer(phase["requests"], 1, 100)
        integer(phase["concurrency"], 1, min(8, phase["requests"]))
        number(phase["rps"], 0.1, 20)
        integer(phase["seconds"], 1, 120)
        require((phase["requests"] - 1) / phase["rps"] < phase["seconds"], "planned starts cannot fit phase duration")
        requests += phase["requests"]
        seconds += phase["seconds"]
        if deployment["environment"] == "production":
            require(value["scenario"] in {"baseline", "load"} and phase["rps"] <= 2 and phase["concurrency"] <= 2,
                    "heavy production workloads are unsupported")
    limits = value["web"]["limits"]
    require(requests <= limits["requests"] and seconds <= min(300, limits["seconds"])
            and requests * limits["response_bytes"] <= limits["body_bytes"], "workload exceeds aggregate budget")
    require(now + seconds + 10 < limits["expires_at"], "authority expires before workload deadline")
    if deployment["environment"] == "production":
        require(requests <= 30 and seconds <= 30, "production read budget exceeds supported ceiling")
    abort = value["abort"]
    fields(abort, {"errors", "latency_ms"})
    integer(abort["errors"], 1, requests)
    number(abort["latency_ms"], 1, limits["timeout_seconds"] * 1000)
    expected = value["acceptance"]
    fields(expected, {"p95_ms", "error_rate", "minimum_success_rps"})
    number(expected["p95_ms"], 1, abort["latency_ms"])
    number(expected["error_rate"], 0, 1)
    number(expected["minimum_success_rps"], 0.01, 20)
    fingerprint(routes[0]["body_sha256"])
    return requests, seconds
