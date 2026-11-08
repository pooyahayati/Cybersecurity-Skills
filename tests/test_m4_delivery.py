import copy
from pathlib import Path
import sys
import unittest

from m4_support import ROOT, RuntimeWorld, Server, compare_roles, roles
from security_assessment.remediation import SourceReview
from security_runtime.common import Blocked, canonical, read_file, sha256


class ObservationDocker:
    """Read-only unit producer; real container effects belong to m4_workflow."""
    def __init__(self, executable):
        self.executable = executable
        self.executable.write_bytes(b"synthetic read-only collector identity; never executed")
        self.image = "sha256:" + "b" * 64
        self.calls = []

    def observe(self):
        return {"executable_sha256": sha256(read_file(self.executable.parent, self.executable.name, 256 * 1024 * 1024)), "endpoint": "synthetic-local-daemon", "client_version": "fixture", "server_version": "fixture"}

    def checked(self, arguments):
        self.calls.append(arguments)
        if arguments[:2] == ["container", "inspect"]:
            return canonical([{"Id": arguments[2], "Image": self.image, "Config": {"User": "1000", "Env": ["SERVICE_SECRET=synthetic-sensitive"]}, "HostConfig": {"ReadonlyRootfs": True}, "State": {"Running": True}}])
        assert arguments == ["image", "inspect", self.image]
        return canonical([{"Id": self.image, "RepoDigests": []}])


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.server = Server(roles())
        self.world = RuntimeWorld(self.server)
        self.docker = ObservationDocker(self.world.root / "fixture-collector.bin")
        self.world.control.docker = self.docker

    def tearDown(self):
        self.server.close(); self.world.close()

    def container(self, name="container", expected=None):
        value = {"id": name, "deployment": "local", "container_id": "c" * 64, "expected_image": expected or self.docker.image, "expires_at": self.world.now[0] + 600}
        return self.world.control.inspect_container("demo", value)

    def release(self):
        return {"id": "release-check", "deployment": "local", "stage": "post-release", "artifact": "sha256:" + "b" * 64, "container": "container", "comparisons": ["roles"], "reviewer": "Synthetic operator", "basis": "Exact local fixture image and separately observed fixture API; no independent URL routing or build provenance."}

    def test_matching_observations_do_not_claim_build_or_url_routing_provenance(self):
        comparison, _result = compare_roles(self.world)
        self.container()
        result = self.world.control.release_check("demo", self.release())
        self.assertTrue(result["declared_correspondence"])
        self.assertFalse(result["deployment_approved"])
        report = self.world.control.runtime_report("demo")
        self.assertTrue(report["releases"][0]["valid"])
        self.assertEqual(report["releases"][0]["bindings"]["source_to_image_provenance"], "not_established")
        self.assertNotIn("synthetic-sensitive", str(report))
        self.assertEqual(self.docker.calls, [["container", "inspect", "c" * 64], ["image", "inspect", "sha256:" + "b" * 64]])
        self.world.control.invalidate_runtime("demo", "web", comparison["cases"][1]["operation"])
        self.assertFalse(self.world.control.runtime_report("demo")["releases"][0]["valid"])

    def test_old_image_and_failed_role_comparison_block_release_correspondence(self):
        self.server.handler = roles(vulnerable=True)
        compare_roles(self.world)
        self.container()
        with self.assertRaises(Blocked): self.world.control.release_check("demo", self.release())
        self.docker.image = "sha256:" + "d" * 64
        self.assertFalse(self.container("old", expected="sha256:" + "b" * 64)["matches_declared_image"])
        request = self.release(); request["container"] = "old"
        with self.assertRaises(Blocked): self.world.control.release_check("demo", request)

    def test_new_container_intent_cannot_repeat_and_current_expiry_is_visible(self):
        self.container()
        with self.assertRaises(Blocked): self.container()
        self.assertEqual(len(self.docker.calls), 2)
        self.world.now[0] += 601
        self.assertFalse(self.world.control.runtime_report("demo")["containers"][0]["valid"])

    def test_authenticated_web_evidence_is_actionable_and_retractable(self):
        self.world.authorize(self.world.authorization([self.world.route(body=b"missing", statuses=[404])]))
        operation = self.world.execute()["operation"]
        record = self.world.state.get("web-operation", operation)
        control = self.world.control_id("web", surface="deployment", deployment="local")
        observation = self.world.observation("web-evidence", control, surface="deployment", files=[], method="deployed_observation")
        observation.update(observed_at=record["finished_at"], expires_at=self.world.now[0] + 500)
        self.world.control.import_runtime_evidence("demo", {"operation": operation, "observation": observation})
        evidence = self.world.control.report("demo")["evidence"][0]
        self.assertEqual(evidence["origin"], "m4_web")
        self.assertTrue(evidence["valid"])
        self.assertIsNone(evidence["execution_exit_code"])
        self.assertEqual(evidence["producer"]["operation"], operation)
        coverage = {"schema_version": 1, "control": control, "state": "reviewed", "outcome": "satisfied",
                    "reason": "Reviewed the complete matched synthetic response.", "evidence": ["web-evidence"]}
        self.world.control.coverage("demo", coverage)
        self.world.control.web.cancel("web-audit")
        self.assertFalse(self.world.control.report("demo")["evidence"][0]["valid"])
        with self.assertRaises(Blocked): self.world.control.coverage("demo", coverage)

    def test_mismatched_web_observation_cannot_satisfy_coverage(self):
        self.world.authorize(self.world.authorization([self.world.route(body=b"expected")]))
        operation = self.world.execute()["operation"]
        record = self.world.state.get("web-operation", operation)
        control = self.world.control_id("web", surface="deployment", deployment="local")
        observation = self.world.observation("mismatch", control, surface="deployment", files=[], method="deployed_observation")
        observation.update(observed_at=record["finished_at"], expires_at=self.world.now[0] + 500)
        self.world.control.import_runtime_evidence("demo", {"operation": operation, "observation": observation})
        coverage = {"schema_version": 1, "control": control, "state": "reviewed", "outcome": "satisfied", "reason": "Synthetic predicate mismatch", "evidence": ["mismatch"]}
        with self.assertRaises(Blocked): self.world.control.coverage("demo", coverage)
        coverage["outcome"] = "failed"
        self.world.control.coverage("demo", coverage)

    def test_older_engine_cannot_skip_new_producer_validation(self):
        with self.assertRaises(Blocked): SourceReview(self.world.state, ROOT).report("demo")
        with self.assertRaises(Blocked): self.world.control.refresh("demo", {})


if __name__ == "__main__": unittest.main()
