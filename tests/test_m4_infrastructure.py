import copy
import unittest

from m4_support import RuntimeWorld, Server
from security_assessment.infrastructure import container_summary, inspect_files, normalize_trivy
from security_runtime.common import Blocked, canonical, digest, sha256


class InfrastructureTests(unittest.TestCase):
    def test_structured_vulnerable_and_safe_near_matches(self):
        pairs = [
            ("workload.json", {"kind": "Pod", "spec": {"containers": [{"securityContext": {"privileged": True}}]}}, "privileged"),
            ("storage.tf.json", {"resource": {"aws_s3_bucket": {"fixture": {"acl": "public-read"}}}}, "public-storage"),
            ("policy.json", {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}, "wildcard-iam"),
            ("network.tf.json", {"ingress": {"from_port": 22, "cidr_blocks": ["0.0.0.0/0"]}}, "open-admin"),
            ("env.json", {"kind": "Pod", "spec": {"env": [{"name": "SERVICE_SECRET", "value": "synthetic-sensitive"}]}}, "secret-config")]
        for path, value, rule in pairs:
            with self.subTest(rule=rule):
                result = inspect_files({path: canonical(value)})
                self.assertIn(rule, [l["rule"] for l in result["leads"]])
                self.assertNotIn("synthetic-sensitive", str(result))
        safe = {"safe.json": canonical({"kind": "Pod", "spec": {"securityContext": {"runAsUser": 1000}, "containers": [{"securityContext": {"privileged": False}, "env": [{"name": "SERVICE_SECRET", "valueFrom": {"secretKeyRef": {"name": "selected"}}}]}]}}),
                "safe.tf.json": canonical({"acl": "private", "ingress": {"from_port": 22, "cidr_blocks": ["10.0.0.0/8"]}}),
                "policy.json": canonical({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})}
        self.assertEqual(inspect_files(safe)["leads"], [])

    def test_pipeline_and_container_build_leaks_without_secret_values(self):
        bad = {"Dockerfile": b"FROM python\nENV SERVICE_SECRET=synthetic-sensitive\nUSER root\n",
               ".github/workflows/build.yml": b"permissions: write-all\nsteps:\n - uses: owner/action@main\n - run: echo '${{ secrets.SERVICE_KEY }}'\n"}
        result = inspect_files(bad)
        self.assertEqual({r["rule"] for r in result["leads"]}, {"root-user", "secret-config", "ci-write-all", "ci-unpinned", "ci-secret-output"})
        self.assertNotIn("synthetic-sensitive", str(result))
        safe = {"Dockerfile": b"FROM python\n# ENV SERVICE_SECRET=comment\nUSER 10001\n", ".github/workflows/build.yml": b"permissions: read-all\n# permissions: write-all\n - uses: owner/action@" + b"a" * 40 + b"\n"}
        self.assertEqual(inspect_files(safe)["leads"], [])

    def test_unknown_format_parse_error_and_source_are_explicit_gaps(self):
        result = inspect_files({"broken.tf.json": b'{"acl":"public-read","acl":"private"}', "app.json": b'{"privileged":true}', "app.py": b"raise Exception('must not execute')"})
        states = {r["path"]: r["status"] for r in result["files"]}
        self.assertEqual(states, {"app.json": "unsupported", "app.py": "unsupported", "broken.tf.json": "inconclusive"})
        self.assertEqual(result["leads"], [])

    def test_scanner_normalization_never_exposes_secret_excerpt_or_hides_no_result(self):
        raw = {"SchemaVersion": 2, "Results": [{"Target": "/inputs/settings.env", "Secrets": [{"RuleID": "fixture-secret", "StartLine": 2, "Match": "synthetic-sensitive", "Code": {"Lines": ["sensitive"]}}]}]}
        result = normalize_trivy(raw, {"settings.env": b"secret=synthetic-sensitive", "other.json": b"{}"}, "1.2.3")
        self.assertNotIn("synthetic-sensitive", str(result))
        self.assertEqual(result["files"][0]["status"], "no_reported_result")
        self.assertEqual(result["leads"][0]["disposition"], "needs_validation")
        raw["Results"][0]["Target"] = "/outside/credential"
        with self.assertRaises(Blocked): normalize_trivy(raw, {"settings.env": b"a"}, "1.2.3")

    def test_container_summary_minimizes_raw_environment_and_host_paths(self):
        container = {"Id": "a" * 64, "Image": "sha256:" + "b" * 64, "Config": {"User": "0", "Env": ["SERVICE_SECRET=synthetic-sensitive"]},
                     "HostConfig": {"Privileged": True, "NetworkMode": "host"}, "Mounts": [{"Source": "/var/run/docker.sock"}], "State": {"Running": True}}
        image = {"Id": container["Image"], "RepoDigests": ["fixture/image@sha256:" + "c" * 64]}
        output = container_summary(container, image)
        self.assertTrue(output["running"])
        self.assertEqual(len(output["leads"]), 5)
        self.assertNotIn("synthetic-sensitive", str(output))
        self.assertNotIn("/var/run/docker.sock", str(output))

    def test_authentic_offline_producer_binding_and_revocation(self):
        server = Server()
        world = RuntimeWorld(server, files={"Dockerfile": b"FROM python\nUSER root\n"})
        try:
            output = inspect_files({"Dockerfile": (world.target / "Dockerfile").read_bytes()})
            operation = world.scan_operation("infra", output)
            world.control.import_infrastructure("demo", {"id": "scan", "operation": operation, "adapter": "infra"})
            self.assertTrue(world.control.runtime_report("demo")["scans"][0]["valid"])
            world.runtime.revoke(component="m4")
            self.assertFalse(world.control.runtime_report("demo")["scans"][0]["valid"])
        finally:
            server.close(); world.close()

    def test_forged_output_missing_candidate_and_changed_source_fail_closed(self):
        for fault in ("output", "candidate", "source"):
            server = Server()
            world = RuntimeWorld(server, files={"Dockerfile": b"FROM python\nUSER 1000\n"})
            try:
                output = inspect_files({"Dockerfile": (world.target / "Dockerfile").read_bytes()})
                operation = world.scan_operation("infra", output)
                world.control.import_infrastructure("demo", {"id": "scan", "operation": operation, "adapter": "infra"})
                if fault == "output": (world.state.root / (operation + ".output")).write_bytes(b"{}")
                elif fault == "source": (world.target / "Dockerfile").write_bytes(b"changed")
                else:
                    with world.state.transaction() as tx:
                        selected = tx.get("active", "m4")
                        tx.connection.execute("DELETE FROM records WHERE kind='candidate' AND id=?", (selected,))
                self.assertFalse(world.control.runtime_report("demo")["scans"][0]["valid"], fault)
            finally:
                server.close(); world.close()


if __name__ == "__main__": unittest.main()
