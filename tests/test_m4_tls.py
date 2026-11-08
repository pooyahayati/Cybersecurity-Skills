import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import unittest

from m4_support import RuntimeWorld, Server
from security_runtime.common import Blocked, sha256


class TlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="cyber-m4-tls-")
        cls.root = Path(cls.temp.name)
        executable = shutil.which("openssl")
        if executable is None and Path("C:/Program Files/Git/usr/bin/openssl.exe").is_file(): executable = "C:/Program Files/Git/usr/bin/openssl.exe"
        if executable is None:
            raise RuntimeError("OpenSSL is required to generate disposable TLS test identities; no TLS check was skipped.")
        for name, alternative in (("valid", "IP:127.0.0.1"), ("wrong", "DNS:wrong.invalid")):
            subprocess.run([executable, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=fixture.invalid",
                "-addext", "subjectAltName=" + alternative, "-keyout", str(cls.root / (name + ".key")), "-out", str(cls.root / (name + ".crt"))],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True, timeout=30)

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def check(self, name, trust, expected):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.root / (name + ".crt"), self.root / (name + ".key"))
        server = Server(tls_context=context)
        world = RuntimeWorld(server)
        try:
            spec = world.authorization([world.route(actor="owner", credential="account")])
            ca = (self.root / (name + ".crt")).read_text(encoding="ascii") if trust else None
            spec["ca_sha256"] = sha256(ca.encode()) if ca else None
            world.authorize(spec)
            credentials = {"account": {"header": "Authorization", "value": "Bearer synthetic-tls-canary"}}
            if expected:
                result = world.execute(credentials=credentials, ca=ca)
                self.assertTrue(result["expectation_matched"])
                observed = world.control.runtime_report("demo")["network"][0]
                self.assertIn(observed["hops"][0]["output"]["tls"]["version"], {"TLSv1.2", "TLSv1.3"})
                self.assertEqual(len(server.calls), 1)
            else:
                with self.assertRaises(Blocked): world.execute(credentials=credentials, ca=ca)
                self.assertEqual(server.calls, [], "TLS failure must occur before an HTTP credential is sent")
        finally:
            server.close(); world.close()

    def test_verified_tls_and_explicit_ca_allow_legitimate_request(self): self.check("valid", True, True)
    def test_untrusted_certificate_prevents_credential_send(self): self.check("valid", False, False)
    def test_hostname_mismatch_prevents_credential_send(self): self.check("wrong", True, False)


if __name__ == "__main__": unittest.main()
