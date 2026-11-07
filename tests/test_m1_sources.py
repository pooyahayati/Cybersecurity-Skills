from copy import deepcopy
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from security_runtime.common import Blocked, canonical, sha256
from security_runtime.sources import GitHub, Http, Transport, source_spec, unpack
from runtime_support import source


class Routes:
    def __init__(self):
        self.calls = []
        commit = {"sha": "a" * 40, "commit": {"tree": {"sha": "b" * 40},
            "committer": {"date": "2026-11-07T00:00:00Z"},
            "verification": {"verified": False, "reason": "unsigned"}}}
        blob = b"print('safe fixture')\n"
        self.routes = {
            "fixture/project": {"id": 10, "owner": {"id": 20}, "full_name": "fixture/project",
                "private": False, "archived": False, "disabled": False, "default_branch": "main"},
            "fixture/project/releases/latest": {"id": 100, "draft": False, "prerelease": False,
                "tag_name": "v1.0.0", "published_at": "2026-11-07T00:00:00Z", "assets": []},
            "fixture/project/git/ref/tags/v1.0.0": {"object": {"type": "commit", "sha": "a" * 40}},
            "fixture/project/git/ref/heads/main": {"object": {"type": "commit", "sha": "a" * 40}},
            "fixture/project/commits/" + "a" * 40: commit,
            "fixture/project/releases?per_page=100&page=1": [],
            "fixture/project/git/trees/" + "b" * 40 + "?recursive=1": {"truncated": False, "tree": [
                {"path": "check.py", "type": "blob", "mode": "100644", "size": len(blob),
                 "sha": hashlib.sha1(b"blob " + str(len(blob)).encode() + b"\0" + blob).hexdigest()}]},
            "raw:fixture/project/" + "a" * 40 + "/check.py": blob,
        }

    def get(self, url, limit=4 * 1024 * 1024, **kwargs):
        key = url.replace("https://api.github.com/repos/", "").replace("https://raw.githubusercontent.com/", "raw:")
        self.calls.append(key)
        if key not in self.routes:
            raise Blocked("unexpected fixture URL")
        value = self.routes[key]
        if value is None:
            return 404, b""
        value = value if isinstance(value, bytes) else canonical(value)
        if len(value) > limit:
            raise Blocked("fixture response too large")
        return 200, value


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.routes = Routes()
        self.github = GitHub(self.routes, clock=lambda: 1794013200)  # 2026-11-07 01:00 UTC
        self.spec = source()

    def test_release_tag_and_actual_blob_verified(self):
        resolved = self.github.resolve(self.spec)
        self.assertEqual(resolved["identity"]["channel"], "stable-release")
        self.assertEqual(self.github.fetch(self.spec, resolved), {"check.py": b"print('safe fixture')\n"})
        self.assertIn("fixture/project/git/ref/tags/v1.0.0", self.routes.calls)
        self.assertFalse(resolved["provenance"]["git_signature_verified"])

    def test_branch_only_after_complete_absence_of_stable_releases(self):
        self.routes.routes["fixture/project/releases/latest"] = None
        result = self.github.resolve(self.spec)
        self.assertEqual(result["identity"]["channel"], "default-branch")
        self.routes.routes["fixture/project/releases?per_page=100&page=1"] = [{"draft": False, "prerelease": False}]
        with self.assertRaises(Blocked):
            self.github.resolve(self.spec)

    def test_unbounded_release_pagination_cannot_fall_back(self):
        self.routes.routes["fixture/project/releases/latest"] = None
        for page in range(1, 11):
            self.routes.routes[f"fixture/project/releases?per_page=100&page={page}"] = [
                {"draft": False, "prerelease": True}] * 100
        with self.assertRaisesRegex(Blocked, "absence"):
            self.github.resolve(self.spec)

    def test_repository_transfer_false_identity_and_private_sources_blocked(self):
        for change in ({"id": 11}, {"owner": {"id": 21}}, {"full_name": "impostor/project"},
                       {"private": True}, {"archived": True}, {"id": True}):
            original = deepcopy(self.routes.routes["fixture/project"])
            self.routes.routes["fixture/project"].update(change)
            with self.subTest(change=change), self.assertRaises(Blocked):
                self.github.resolve(self.spec)
            self.routes.routes["fixture/project"] = original

    def test_prerelease_cannot_satisfy_stable(self):
        self.routes.routes["fixture/project/releases/latest"]["prerelease"] = True
        with self.assertRaises(Blocked):
            self.github.resolve(self.spec)

    def test_annotated_tag_peeling_and_cycles(self):
        self.routes.routes["fixture/project/git/ref/tags/v1.0.0"]["object"] = {"type": "tag", "sha": "c" * 40}
        self.routes.routes["fixture/project/git/tags/" + "c" * 40] = {"object": {"type": "commit", "sha": "a" * 40}}
        self.assertEqual(self.github.resolve(self.spec)["identity"]["revision"], "a" * 40)
        self.routes.routes["fixture/project/git/tags/" + "c" * 40]["object"] = {"type": "tag", "sha": "c" * 40}
        with self.assertRaises(Blocked):
            self.github.resolve(self.spec)

    def test_stale_data_and_future_metadata_blocked(self):
        spec = source("rules", "data")
        spec["data_max_age_seconds"] = 60
        with self.assertRaisesRegex(Blocked, "too old"):
            self.github.resolve(spec)
        self.routes.routes["fixture/project/releases/latest"]["published_at"] = "2026-11-08T00:00:00Z"
        with self.assertRaisesRegex(Blocked, "future"):
            self.github.resolve(self.spec)

    def test_truncated_tree_links_missing_resources_and_wrong_bytes_blocked(self):
        resolved = self.github.resolve(self.spec)
        tree_key = "fixture/project/git/trees/" + "b" * 40 + "?recursive=1"
        original = deepcopy(self.routes.routes[tree_key])
        for changed in ({"truncated": True}, {"tree": []}, {"tree": [
                {"path": "check.py", "type": "blob", "mode": "120000", "size": 5, "sha": "d" * 40}]}):
            self.routes.routes[tree_key] = {**original, **changed}
            with self.subTest(changed=changed), self.assertRaises(Blocked):
                self.github.fetch(self.spec, resolved)
        self.routes.routes[tree_key] = original
        self.routes.routes["raw:fixture/project/" + "a" * 40 + "/check.py"] = b"claims version 1.0.0 but changed"
        with self.assertRaises(Blocked):
            self.github.fetch(self.spec, resolved)

    def test_release_asset_requires_and_checks_official_digest(self):
        self.spec.update(include=[], asset={"name": "tool-{version}.bin", "format": "raw", "members": ["tool"]})
        asset = {"id": 55, "name": "tool-1.0.0.bin", "size": 5, "digest": "sha256:" + sha256(b"valid")}
        self.routes.routes["fixture/project/releases/latest"]["assets"] = [asset]
        self.routes.routes["fixture/project/releases/assets/55"] = b"valid"
        resolved = self.github.resolve(self.spec)
        self.assertEqual(self.github.fetch(self.spec, resolved), {"tool": b"valid"})
        self.routes.routes["fixture/project/releases/assets/55"] = b"false"
        with self.assertRaises(Blocked):
            self.github.fetch(self.spec, resolved)
        asset["digest"] = None
        with self.assertRaises(Blocked):
            self.github.resolve(self.spec)

    def test_blob_transport_enforces_verified_size_before_hashing(self):
        resolved = self.github.resolve(self.spec)
        self.routes.routes["raw:fixture/project/" + "a" * 40 + "/check.py"] = b"x" * 128
        with self.assertRaisesRegex(Blocked, "fixture response too large"):
            self.github.fetch(self.spec, resolved)

    def test_empty_blob_has_zero_byte_acquisition_budget(self):
        tree = self.routes.routes["fixture/project/git/trees/" + "b" * 40 + "?recursive=1"]
        tree["tree"][0].update(size=0, sha=hashlib.sha1(b"blob 0\0").hexdigest())
        self.routes.routes["raw:fixture/project/" + "a" * 40 + "/check.py"] = b""
        resolved = self.github.resolve(self.spec)
        self.assertEqual(self.github.fetch(self.spec, resolved), {"check.py": b""})


class AcquisitionTests(unittest.TestCase):
    def test_http_redirect_denied_and_storage_token_not_forwarded(self):
        calls = []

        class Opener:
            def open(self, req, **kwargs):
                calls.append(req)
                if len(calls) == 1:
                    raise HTTPError(req.full_url, 302, "redirect", {
                        "Location": "https://release-assets.githubusercontent.com/fixture?signature=synthetic"}, None)
                raise OSError("fixture stop before network")

        with patch("urllib.request.build_opener", return_value=Opener()):
            with self.assertRaises(Blocked):
                Transport("synthetic-test-token").get("https://api.github.com/repos/fixture/project/releases/assets/55", asset=True)
        self.assertEqual(calls[0].get_header("Authorization"), "Bearer synthetic-test-token")
        self.assertIsNone(calls[1].get_header("Authorization"))
        calls.clear()
        with patch("urllib.request.build_opener", return_value=Opener()):
            with self.assertRaises(Blocked):
                Transport().get("https://api.github.com/repos/fixture/project")
        self.assertEqual(len(calls), 1)

    def test_nonofficial_url_rejected_before_network(self):
        for url in ("http://api.github.com/x", "https://api.github.com.evil/x", "https://user@api.github.com/x",
                    "https://127.0.0.1/x", "https://api.github.com:443/x"):
            with self.subTest(url=url), self.assertRaises(Blocked):
                Transport().get(url)

    def zip(self, entries):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for name, content in entries:
                archive.writestr(name, content)
        return output.getvalue()

    def test_zip_selection_and_traversal_case_link_size_denials(self):
        selection = {"format": "zip", "members": ["bin/tool"]}
        self.assertEqual(unpack(self.zip([("bin/tool", b"fixture")]), selection, 64), {"bin/tool": b"fixture"})
        for entries in ([('bin/tool', b'fixture'), ('../escape', b'x')],
                        [('bin/tool', b'a'), ('BIN/TOOL', b'b')], [('bin/tool', b'x' * 65)]):
            with self.subTest(entries=entries), self.assertRaises(Blocked):
                unpack(self.zip(entries), selection, 64)
        link = zipfile.ZipInfo("bin/tool")
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        with self.assertRaises(Blocked):
            unpack(self.zip([(link, b"/outside")]), selection, 64)

    def test_tar_link_and_compression_bomb_denied(self):
        selection = {"format": "tar.gz", "members": ["tool"]}
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            info = tarfile.TarInfo("tool")
            info.type, info.linkname = tarfile.SYMTYPE, "/outside"
            archive.addfile(info)
        with self.assertRaises(Blocked):
            unpack(output.getvalue(), selection, 64)
        with self.assertRaisesRegex(Blocked, "expanded limit"):
            unpack(gzip.compress(b"\0" * (5 * 1024 * 1024)), selection, 64)

    def test_valid_tar_selected_without_install_hooks(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name, data in (("tool", b"fixture"), ("install.sh", b"never executed")):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        self.assertEqual(unpack(output.getvalue(), {"format": "tar.gz", "members": ["tool"]}, 1024),
                         {"tool": b"fixture"})

    def test_unsupported_encrypted_member_fails_without_echoing_its_name(self):
        marker = "private-filename-marker"
        # Set encryption flags in both headers of a synthetic single-member ZIP.
        content = bytearray(self.zip([(marker, b"value")]))
        content[6:8] = (1).to_bytes(2, "little")
        central = content.index(b"PK\x01\x02")
        content[central + 8:central + 10] = (1).to_bytes(2, "little")
        with self.assertRaises(Blocked) as failure:
            unpack(bytes(content), {"format": "zip", "members": [marker]}, 1024)
        self.assertNotIn(marker, str(failure.exception))


if __name__ == "__main__":
    unittest.main()
