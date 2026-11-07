#!/usr/bin/env python3
"""Offline M1 demonstration: fingerprint one synthetic snapshot, not a security scan."""

import hashlib
import json
from pathlib import Path

content = Path("/inputs/example.txt").read_bytes()
print(json.dumps({"operation": "snapshot-demonstration", "bytes": len(content),
                  "sha256": hashlib.sha256(content).hexdigest(), "security_assessment": False}))
