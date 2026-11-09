#!/usr/bin/env python3
"""Actual current Trivy/advisory and Cosign workers through unchanged offline M1.

Only the unmerged head/worker and owned publisher policy use a synthetic publisher.
Tool and advisory identity is resolved live; optional acquired bytes must match it.
"""

import argparse
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from m4_support import ROOT,RuntimeWorld,Server
from runtime_support import acceptance,source
from security_assessment.checklist_runtime import ChecklistReview
from security_runtime.advisory import Advisory
from security_runtime.common import Blocked,canonical,digest,parse,read_file,require,sha256
from security_runtime.controller import selected_tree
from security_runtime.sandbox import Docker
from security_runtime.sources import GitHub,Http,unpack


class Publisher:
    def __init__(self,fixture,archives):
        self.fixture,self.archives=fixture,archives
        self.official=GitHub(Http(os.environ.get('GITHUB_TOKEN')))
    def resolve(self,spec):
        return self.official.resolve(spec) if spec['id'] in {'trivy','trivy-db','cosign'} else self.fixture.resolve(spec)
    def fetch(self,spec,resolved):
        key=spec['id']
        if key not in {'trivy','trivy-db','cosign'}:return self.fixture.fetch(spec,resolved)
        path=self.archives.get(key)
        if path is None:return self.official.fetch(spec,resolved)
        raw=read_file(path.parent,path.name,spec['max_download_bytes'])
        if key=='trivy-db':
            expected=resolved['identity']['layer']
            require(len(raw)==expected['size'] and 'sha256:'+sha256(raw)==expected['digest'],'provided advisory is not the current official layer')
            return {'db.tar.gz':raw}
        expected=resolved['identity']['asset']
        require(len(raw)==expected['size'] and sha256(raw)==expected['sha256'],'provided tool is not the current official asset')
        return unpack(raw,spec['asset'],spec['max_unpacked_bytes'])


def signing_fixture(path,revision):
    path.mkdir()
    openssl=shutil.which('openssl') or (r'C:\Program Files\Git\usr\bin\openssl.exe' if os.name=='nt' else None)
    require(openssl and Path(openssl).is_file(),'owned signing fixture requires OpenSSL')
    def run(args):
        result=subprocess.run([openssl,*args],capture_output=True,timeout=15)
        require(result.returncode==0,'owned signing fixture generation failed');return result.stdout
    run(['ecparam','-name','prime256v1','-genkey','-noout','-out',str(path/'key.pem')])
    run(['pkey','-in',str(path/'key.pem'),'-pubout','-out',str(path/'publisher.pub')])
    artifact=b'Owned synthetic artifact; no executable target code.'
    key=(path/'publisher.pub').read_bytes()
    policy={'schema_version':1,'publisher':'Owned qualification publisher','key_sha256':sha256(key),'artifact_name':'owned.bin',
        'predicate_type':'https://slsa.dev/provenance/v1','builder':'owned-builder','source_uri':'https://example.invalid/owned',
        'source_revision':revision,'workflow':'owned-build'}
    statement={'_type':'https://in-toto.io/Statement/v1','subject':[{'name':'owned.bin','digest':{'sha256':sha256(artifact)}}],
        'predicateType':policy['predicate_type'],'predicate':{'buildDefinition':{'buildType':'owned-build',
        'resolvedDependencies':[{'uri':policy['source_uri'],'digest':{'gitCommit':revision}}]},'runDetails':{'builder':{'id':'owned-builder'}}}}
    (path/'attestation.json').write_bytes(canonical(statement))
    signature=run(['dgst','-sha256','-sign',str(path/'key.pem'),str(path/'attestation.json')])
    der=run(['pkey','-pubin','-in',str(path/'publisher.pub'),'-outform','DER'])
    b64=lambda data:base64.b64encode(data).decode()
    bundle={'mediaType':'application/vnd.dev.sigstore.bundle.v0.3+json','verificationMaterial':{'publicKey':{'hint':b64(bytes.fromhex(sha256(der)))},'tlogEntries':[]},
        'messageSignature':{'messageDigest':{'algorithm':'SHA2_256','digest':b64(bytes.fromhex(digest(statement)))},'signature':b64(signature)}}
    return {'artifact.bin':artifact,'attestation.json':canonical(statement),'attestation.bundle.json':canonical(bundle)}, {'publisher.pub':key,'policy.json':canonical(policy)}


def run(executable,archives,retain=False):
    server=Server();world=RuntimeWorld(server);server.close()
    docker=Docker(executable,world.state);publisher=Publisher(world.publisher,archives)
    world.runtime.docker=docker;world.runtime.upstream=publisher;world.runtime.clock=time.time
    control=ChecklistReview(world.state,ROOT,upstream=publisher,docker=docker)
    done=False;results=[]
    try:
        world.publisher.contents['c26']={p:read_file(ROOT,p) for p in selected_tree(ROOT,['scripts'])}
        world.runtime.enroll(source('c26','tool',['scripts']))
        trivy=source('trivy');trivy.update(repository='aquasecurity/trivy',repository_id=180687624,owner_id=12783832,include=[],
            asset={'name':'trivy_{version}_Linux-64bit.tar.gz','format':'tar.gz','members':['trivy']},max_download_bytes=128*1024**2,max_unpacked_bytes=512*1024**2)
        for spec in (trivy,parse(read_file(ROOT,'config/trivy-db-source.json')),parse(read_file(ROOT,'config/cosign-source.json'))):world.runtime.enroll(spec)
        fixture,policy=signing_fixture(world.root/'signing','a'*40)
        world.publisher.contents['publisher-policy']=policy
        world.runtime.enroll(source('publisher-policy','tool',list(policy)))
        for component in ('runtime','c26','trivy','trivy-db','cosign','publisher-policy'):
            candidate=world.runtime.prepare(component)['candidate'];review=acceptance(candidate)
            for area in review['checks']:
                review['checks'][area]['evidence']='Owned qualification only: exact current official resource identity; upstream license reviewed; fixed offline worker; independent policy/data; no target hooks or network.'
            world.runtime.review(review);world.runtime.activate(candidate)
            print(json.dumps({'prepared':component,'candidate':candidate}),flush=True)
        def execute(key,files,stage,expected_success=True):
            target=world.root/key;target.mkdir()
            for name,data in files.items():(target/name).write_bytes(data)
            # These target-controlled suppression/hook files are deliberately not admitted inputs.
            (target/'trivy.yaml').write_bytes(b'scan:\n  scanners: []\n')
            (target/'.trivyignore').write_bytes(b'CVE-2021-23337\n')
            (target/'target-hook.py').write_bytes(b'raise RuntimeError("TARGET_HOOK_MUST_NOT_RUN")\n')
            spec=copy.deepcopy(world.spec);spec['id']=key;spec['source'].update(root=str(target),files=sorted(files),revision='a'*40)
            control.create(spec)
            components=['c26','trivy','trivy-db'] if stage=='c2' else ['c26','cosign','publisher-policy']
            world.runtime.authorize({'id':key,'root':str(target),'inputs':sorted(files),'components':components,'network':'none',
                'operations':[{'id':'inspect','component':'c26','entrypoint':'scripts/'+stage+'_worker.py','interpreter':'python','arguments':[],
                    'timeout_seconds':150,'max_output_bytes':8*1024**2}],
                'limits':{'calls':1,'seconds':150,'expires_at':time.time()+1200,'memory_mb':2048,'cpus':2,'pids':128,'tmpfs_mb':256}})
            session=world.runtime.begin(key)['run'];operation=world.runtime.execute(session,'inspect')['operation']
            actual=world.state.get('operation',operation)['result']['exit_code']==0
            require(actual==expected_success,'actual worker result differs for '+key)
            if actual:
                result=control.offline(key,operation,stage);results.append(result)
                return world.state.get('checklist-execution',operation)['report']
            try:control.offline(key,operation,stage)
            except Blocked:pass
            else:raise AssertionError('failed actual verifier imported successfully')
            results.append({'id':key,'blocked_import':True});return None
        for version in ('4.17.20','4.17.21'):
            lock={'name':'owned','lockfileVersion':3,'packages':{'':{'name':'owned'},'node_modules/lodash':{'version':version}}}
            report=execute('dependency-'+version.replace('.','-'),{'package-lock.json':canonical(lock)},'c2')
            matches=[row for row in report['findings'] if row['advisory']=='CVE-2021-23337']
            require(bool(matches)==(version=='4.17.20'),'known vulnerable/fixed advisory attribution differs')
            require(all(row['location']=='node_modules/lodash' and row['version']==version for row in report['findings']),'wrong exact dependency attribution')
        report=execute('provenance-valid',fixture,'c5');require(report['outcome']=='satisfied','approved signature failed')
        execute('provenance-altered-artifact',{**fixture,'artifact.bin':fixture['artifact.bin']+b'tampered'},'c5',False)
        bad=copy.deepcopy(fixture);value=parse(bad['attestation.bundle.json']);value['messageSignature']['signature']=base64.b64encode(b'wrong-signature').decode();bad['attestation.bundle.json']=canonical(value)
        execute('provenance-forged-signature',bad,'c5',False)
        execute('provenance-wrong-builder',{**fixture,'attestation.json':fixture['attestation.json'].replace(b'owned-builder',b'wrong-builder')},'c5',False)
        # A changed enrolled publisher policy must block; it is never a target assertion.
        world.publisher.revisions['publisher-policy']='b'*64
        try:world.runtime.begin('provenance-valid')
        except Blocked:pass
        else:raise AssertionError('changed publisher policy reused')
        done=True;print(json.dumps({'status':'passed','actual_operations':len(results),'results':results}),flush=True)
    finally:
        world.runtime.recover()
        if retain or not done:print(json.dumps({'retained_private_evidence':str(world.root)}),flush=True)
        else:world.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--docker',type=Path,required=True)
    for name in ('trivy','trivy-db','cosign'):parser.add_argument('--'+name+'-archive',type=Path)
    parser.add_argument('--retain',action='store_true');args=parser.parse_args()
    archives={name:getattr(args,name.replace('-','_')+'_archive') for name in ('trivy','trivy-db','cosign')}
    run(args.docker,{key:value.resolve(strict=True) for key,value in archives.items() if value},args.retain)
