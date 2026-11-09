#!/usr/bin/env python3
"""Offline Cosign signature plus independently reviewed SLSA policy."""

import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from security_assessment.provenance import match
from security_runtime.common import parse,read_file,require
from security_runtime.process import bounded_process


def verify():
    # Policy and approved public key are separate reviewed resources, not artifact assertions.
    expected=parse(read_file('/resources/publisher-policy','policy.json',16384))
    key=read_file('/resources/publisher-policy','publisher.pub',16384)
    statement=read_file('/inputs','attestation.json',1024*1024)
    artifact=read_file('/inputs','artifact.bin',64*1024*1024)
    signature=read_file('/inputs','attestation.bundle.json',65536)
    require(signature,'signature unavailable')
    facts=match(statement,artifact,key,expected)
    env={'PATH':'/usr/bin:/bin','HOME':'/tmp','TMPDIR':'/tmp'}
    binary='/resources/cosign/cosign'
    version=bounded_process([binary,'version','--json'],env,10,16384)
    require(version['exit_code']==0,'verifier version unavailable')
    result=bounded_process([binary,'verify-blob','--key','/resources/publisher-policy/publisher.pub',
        '--bundle','/inputs/attestation.bundle.json','--insecure-ignore-tlog=true','/inputs/attestation.json'],env,30,65536)
    require(result['exit_code']==0,'artifact provenance signature failed')
    return {'schema_version':1,'adapter':'c5-cosign-public-key','outcome':'satisfied','facts':facts,
        'tool_version':parse(version['content']),'limits':['Approved key binding only; no transparency, keyless issuer, deployed artifact, or hosted pipeline claim.']}


if __name__=='__main__':
    try:
        require(len(sys.argv)==1,'invalid arguments')
        print(json.dumps(verify(),allow_nan=False))
    except Exception:
        print('{"status":"unavailable"}')
        raise SystemExit(1)
