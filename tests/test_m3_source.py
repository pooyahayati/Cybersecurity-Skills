import unittest

from m2_support import ROOT
from security_assessment.source_rules import inspect_sources


class SourceRulesTests(unittest.TestCase):
    def test_vulnerable_safe_pairs(self):
        pairs = [
            ("py", "dynamic-code", "eval(request)", "json.loads(request)"),
            ("py", "unsafe-deserialization", "pickle.loads(data)", "json.loads(data)"),
            ("py", "dynamic-query", 'cursor.execute(f"SELECT * FROM users WHERE id={user}")', 'cursor.execute("SELECT * FROM users WHERE id=?", (user,))'),
            ("py", "embedded-secret", 'api_key = "synthetic-credential"', 'api_key = os.environ["API_KEY"]'),
            ("py", "session-cookie", 'app.config["SESSION_COOKIE_SECURE"] = False', 'app.config["SESSION_COOKIE_SECURE"] = True'),
            ("py", "sensitive-log", "logger.info(password)", "logger.info(event_id)"),
            ("js", "dynamic-code", "eval(input);", "JSON.parse(input);"),
            ("ts", "embedded-secret", 'const token = "synthetic-credential";', 'const token = process.env.TOKEN;'),
            ("ts", "session-cookie", "session({httpOnly: false});", "session({httpOnly: true});"),
            ("php", "unsafe-deserialization", "<?php unserialize($input);", "<?php json_decode($input);"),
            ("php", "embedded-secret", '<?php $password = "synthetic-credential";', '<?php $password = getenv("PASSWORD");'),
            ("php", "session-cookie", "<?php ini_set('session.cookie_httponly', 0);", "<?php ini_set('session.cookie_httponly', 1);")]
        for ext, rule, bad, safe in pairs:
            with self.subTest(ext=ext, rule=rule):
                result = inspect_sources({"bad." + ext: bad.encode(), "safe." + ext: safe.encode()})
                self.assertEqual([(x["path"], x["rule"]) for x in result["leads"]], [("bad." + ext, rule)])
                self.assertNotIn("synthetic-credential", str(result))
                self.assertTrue(all(f["status"] in ("examined", "limited_lexical") for f in result["files"]))

    def test_comments_strings_never_become_code(self):
        for ext in ("js", "ts", "php"):
            result = inspect_sources({"safe." + ext: b'// eval(input);\n/* unserialize(data) */\nlet example = "eval(input)";\n'})
            self.assertEqual(result["leads"], [])
        self.assertEqual(inspect_sources({"safe.py": b'# eval(input)\nexample = "eval(input)"\n'})["leads"], [])

    def test_parse_failure_unsupported_and_no_execution(self):
        result = inspect_sources({"broken.py": b"def ???", "opaque.py": b"\xff", "unknown.rb": b"eval(input)", "marker.py": b"raise RuntimeError('must never run')"})
        self.assertEqual([f["status"] for f in result["files"]], ["inconclusive", "examined", "inconclusive", "unsupported"])
        self.assertEqual(result["security_verdict"], "not_established")

    def test_input_bounds(self):
        for contents in ({}, {"large.py": b" " * (1024 * 1024 + 1)}, {str(i) + ".py": b"" for i in range(257)}):
            with self.assertRaises(ValueError): inspect_sources(contents)

    def test_m3_typed_states_survive_masking_but_identifiers_do_not(self):
        from security_assessment.redaction import redact
        row = {"domain": "identity", "scope": "declared_serialized_model", "conclusion": "supported_issue", "variant": "candidate", "origin": "operator_source_review", "id": "candidate", "summary": "identity candidate"}
        result = redact(row, list(row.values()))
        for field in ("domain", "scope", "conclusion", "variant", "origin"):
            self.assertEqual(result[field], row[field])
        self.assertEqual(result["id"], "[REDACTED]")
        self.assertNotIn("candidate", result["summary"])

    def test_exact_versions_reject_moving_tags_and_ranges(self):
        from security_assessment.remediation import exact_version
        for ecosystem, versions in {"npm": ["1.2.3", "0.0.1-rc.2+build.4"], "pypi": ["1.2.3", "2!1.4rc1.post2.dev3+build.1"], "composer": ["v1.2.3", "1.2.0-RC1"]}.items():
            for value in versions: exact_version(ecosystem, value)
            for value in ("latest", "main", "1.x", "1.*", "^1.2", ">=1.2", "1.2 || 2.0", "dev-main", "1.2.3\n"):
                with self.subTest(ecosystem=ecosystem, value=value), self.assertRaises(ValueError): exact_version(ecosystem, value)


if __name__ == "__main__": unittest.main()
