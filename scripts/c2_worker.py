#!/usr/bin/env python3
"""M1 offline dependency scan using separately reviewed tool and OCI data."""

import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security_assessment.dependencies import inventory, normalize
from security_runtime.advisory import validate_metadata
from security_runtime.common import parse, read_file, require
from security_runtime.process import bounded_process


def scan():
    # Only this exact file is analyzed. Target hooks/config/plugins are never loaded.
    raw = read_file('/inputs', 'package-lock.json', 4 * 1024**2)
    selected = inventory(raw)
    metadata = validate_metadata(read_file('/resources/trivy-db', 'db/metadata.json', 16384),
                                 {'data_max_age_seconds': 86400}, time.time(), time.time())
    target = Path('/tmp/c2-input')
    target.mkdir()
    (target / 'package-lock.json').write_bytes(raw)
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/tmp', 'TMPDIR': '/tmp'}
    binary = '/resources/trivy/trivy'
    version = bounded_process([binary, 'version', '--config=', '--quiet', '--cache-dir', '/resources/trivy-db', '--format', 'json'], env, 10, 16384)
    require(version['exit_code'] == 0, 'scanner identity unavailable')
    result = bounded_process([binary, 'filesystem', '--config=', '--ignorefile=', '--disable-telemetry', '--skip-db-update',
        '--skip-java-db-update', '--skip-check-update', '--offline-scan', '--include-dev-deps', '--scanners', 'vuln',
        '--list-all-pkgs', '--format', 'json', '--quiet', '--cache-dir', '/resources/trivy-db', '--exit-code', '0', str(target)], env, 120, 6 * 1024**2)
    require(result['exit_code'] == 0, 'offline dependency scan failed')
    return normalize(parse(result['content'], 6 * 1024**2), selected, parse(version['content']).get('Version'), metadata)


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 1, 'invalid arguments')
        print(json.dumps(scan(), allow_nan=False))
    except Exception:
        print('{"status":"unavailable"}')
        raise SystemExit(1)
