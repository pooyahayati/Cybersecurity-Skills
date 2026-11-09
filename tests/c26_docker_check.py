#!/usr/bin/env python3
"""Actual current-runtime C4/C5/C6 qualification on owned disposable services."""

import argparse
from contextlib import closing
import copy
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import time
from urllib.request import urlopen

sys.path.insert(0,str(Path(__file__).resolve().parent))
from c26_support import ScenarioWorld,TABLES
from runtime_support import acceptance
from security_runtime.common import canonical,digest,parse,sha256,require
from security_runtime.detection import DetectionListeners
from security_runtime.sandbox import Docker


def free_port():
    with socket.socket() as conn:conn.bind(('127.0.0.1',0));return conn.getsockname()[1]


class DockerApp:
    def __init__(self,root,mode,docker,identity,database=None,source=None,port=None):
        self.root=Path(root);self.root.mkdir();self.docker=docker;self.container=None
        self.source=source or self.root/'source'
        if source is None:
            self.source.mkdir()
            raw=(Path(__file__).with_name('fixtures')/'c26_app.py').read_bytes().replace(b"MODE='fixed'",("MODE='"+mode+"'").encode())
            (self.source/'app.py').write_bytes(raw)
        self.database=database or self.root/'application.sqlite3'
        if database is None:self.database.write_bytes(b'')
        self.database.chmod(0o666)
        for path in (self.root,self.source):path.chmod(0o755)
        (self.source/'app.py').chmod(0o644)
        self.port=port or free_port();self.url='http://127.0.0.1:'+str(self.port)+'/'
        self.command=['-I','-B','/app/app.py','/tmp/application.sqlite3','--port','8080','--host','0.0.0.0']
        args=['run','--detach','--rm','--label','org.pooyahayati.cybersecurity.fixture=c26','--user','65532:65532',
            '--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--network','bridge','--pids-limit','32',
            '--memory','128m','--cpus','0.5','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=32m',
            '--mount','type=bind,src='+str(self.source)+',dst=/app,readonly',
            '--mount','type=bind,src='+str(self.database)+',dst=/tmp/application.sqlite3',
            '--publish','127.0.0.1:'+str(self.port)+':8080','--entrypoint','/usr/local/bin/python',identity['reference'],*self.command]
        self.container=docker.checked(args).decode().strip()
        try:
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                try:
                    with urlopen(self.url+'health',timeout=.5):return
                except Exception:time.sleep(.1)
            raise RuntimeError('actual Docker service readiness failed')
        except Exception:self.close();raise
    def request(self,key):
        return {'id':key,'deployment':'local','container':self.container,'source_mount':'/app','database_mount':'/tmp/application.sqlite3',
            'entrypoint':['/usr/local/bin/python'],'command':self.command}
    def close(self):
        if self.container:
            self.docker.checked(['container','rm','--force',self.container]);self.container=None


class DockerWorld(ScenarioWorld):
    def __init__(self,executable):
        super().__init__()
        self.docker=Docker(executable,self.world.state);self.world.runtime.docker=self.docker
        runtime=self.world.runtime.prepare('runtime')['candidate'];self.world.runtime.review(acceptance(runtime));self.world.runtime.activate(runtime)
        self.identity=self.world.runtime.candidate(runtime)['resolved']['identity']
        self.control.docker=self.docker;self.control.traffic.controller.docker=self.docker
        self.control.traffic.binding_validator=self.control.validate_binding
        self.factory=lambda root,mode:DockerApp(root,mode,self.docker,self.identity)
    def add(self,key,mode):
        app=self.factory(self.world.root/key,mode);self.apps.append(app)
        spec=copy.deepcopy(self.world.spec);spec['id']=key
        spec['source'].update(root=str(app.source),files=['app.py'],revision=sha256((app.source/'app.py').read_bytes())[:40])
        spec['deployments'][0].update(url=app.url,artifact=self.identity['image_id'])
        self.control.create(spec);case=self.control.case(key)
        result=self.control.bind_deployment(key,app.request(key))
        require(result['outcome']=='satisfied','legitimate effective service configuration failed')
        return app,case


def traffic(world,case,key,deployment,url,credential=None,body=None,credentials=None):
    raw=b'' if body is None else canonical(body)
    spec={'schema_version':1,'id':key,'deployment':deployment,'profile':'scenario','addresses':['127.0.0.1'],'network':'loopback','ca_sha256':None,
        'routes':[{'id':key,'url':url,'method':'GET' if body is None else 'POST','credential':credential,'body_sha256':sha256(raw),
            'effect':'read' if body is None else 'synthetic-write'}],
        'limits':{'requests':1,'seconds':15,'response_bytes':16384,'total_body_bytes':65536,'timeout_seconds':5,'interval_ms':100,'concurrency':1,'expires_at':time.time()+600}}
    world.control.traffic.authorize(case,spec)
    return world.control.traffic.execute(case,key,key,raw,credentials)['operation']


def recovery(world):
    app,oldcase=world.add('recovery-source','fixed');port=free_port();restored_url='http://127.0.0.1:'+str(port)+'/'
    spec=copy.deepcopy(oldcase['scope']);spec['id']='recovery'
    spec['deployments'].append({'id':'restored','environment':'local','url':restored_url,'artifact':world.identity['image_id']})
    world.control.create(spec);case=world.control.case('recovery')
    world.control.bind_deployment('recovery',app.request('source-binding'))
    credentials={label:{'header':'Authorization','value':'Bearer '+token} for label,token in [('old','recovery-old'),('new','recovery-new'),('admin','alice-session')]}
    prior=traffic(world,case,'prior','local',app.url+'state','old',credentials=credentials)
    service=world.control.service_recovery
    service.capture(case,{'id':'restore','application_binding':'source-binding','oracle':{'path':str(app.database),'tables':{'events':['id','data']}},
        'watermark_table':'events','watermark_column':'id','max_loss_events':1,'max_recovery_seconds':120,
        'service_expectation':{'body_sha256':digest({'events':[[1,'synthetic-first']]}),'denial_body_sha256':digest({'error':'denied'}),
            'allowed_credential':'new','compromised_credential':'old','compromised_prior_operation':prior,'deployment':'restored'}})
    with closing(sqlite3.connect(app.database)) as db,db:db.execute('INSERT INTO events VALUES (2,"after-backup")')
    result=service.restore(case,'restore')
    restored=DockerApp(world.world.root/'restored','fixed',world.docker,world.identity,database=Path(result['restored_path']),source=app.source,port=port)
    world.apps.append(restored)
    request=restored.request('restored-binding');request['deployment']='restored'
    world.control.bind_deployment('recovery',request)
    traffic(world,case,'rotate','restored',restored.url+'secrets/rotate','admin',{},credentials)
    positive=traffic(world,case,'positive','restored',restored.url+'state','new',credentials=credentials)
    negative=traffic(world,case,'negative','restored',restored.url+'state','old',credentials=credentials)
    proof=world.control.backup_access('recovery','restore','restored-binding')
    result=service.finish(case,'restore',positive,negative,proof['operation'],'restored-binding')
    require(result['outcome']=='satisfied','actual application restore failed')
    app.close();restored.close();return result


def detection(world):
    app,case=world.add('detection','fixed');service=world.control.service_recovery
    service.plan_detection(case,{'id':'exercise','event':'owned-audit','hops':['target','collector','receiver'],'owner':'Owned qualification operator',
        'timeout_seconds':120,'application_binding':'detection','target_path':'/audit-exercise'})
    record=world.world.state.get('detection-exercise','exercise')
    listeners=DetectionListeners(world.world.state,'exercise',lambda:world.control.validate_binding(case,'detection'))
    address=listeners.start()
    # Docker Desktop proxies its host endpoint to the owned loopback listener.
    # On Linux the qualification harness must share the target's network namespace.
    if os.name=='nt':address=address.replace('127.0.0.1','host.docker.internal')
    else:raise RuntimeError('Linux target/collector namespace bridge must be explicitly configured')
    try:
        with closing(sqlite3.connect(app.database)) as db,db:
            db.execute('INSERT INTO audit_config VALUES (1,?)',(canonical({'expected':record['expected'],'event':record['event'],
                'target_key':record['keys']['target'],'collector':address}).decode(),))
        operation=traffic(world,case,'event','local',app.url+'audit-exercise',body=record['event'])
        with closing(sqlite3.connect(app.database)) as db:
            row=db.execute('SELECT data FROM audit_events WHERE id=?',('exercise',)).fetchone()
        require(row,'actual target did not persist its audit event')
        target=world.world.root/'target-audit.jsonl';target.write_bytes(row[0].encode()+b'\n')
        paths={hop:str(world.world.state.root/('detection-exercise-'+hop+'.jsonl')) for hop in ('collector','receiver')};paths['target']=str(target)
        result=service.detection(case,'exercise',paths,operation);require(result['outcome']=='satisfied','actual alert path failed')
        return result
    finally:listeners.close();app.close()


def run(executable,sections,retain=False):
    world=DockerWorld(executable);results=[]
    try:
        if 'scenarios' in sections:
            for index,family in enumerate(TABLES):
                stamp=int(time.time())
                original=world.run('original-'+str(index),'vulnerable',family,stamp)
                candidate=world.run('candidate-'+str(index),'fixed',family,stamp)
                require(original['outcome']=='failed' and candidate['outcome']=='satisfied','actual original/fixed behavior differs')
                compared=world.control.traffic.compare(original['operation'],candidate['operation'])
                results.append({'family':family,**compared});print(json.dumps(results[-1]),flush=True)
                world.apps[-2].close();world.apps[-1].close()
        if 'recovery' in sections:results.append(recovery(world));print(json.dumps(results[-1]),flush=True)
        if 'detection' in sections:results.append(detection(world));print(json.dumps(results[-1]),flush=True)
        print(json.dumps({'status':'passed','sections':sections,'runtime':world.identity,'results':len(results)}))
    finally:
        if retain:
            for app in world.apps:app.close()
            print(json.dumps({'retained_private_evidence':str(world.world.root)}),flush=True)
        else:world.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--docker',type=Path,required=True)
    parser.add_argument('--sections',nargs='+',choices=['scenarios','recovery','detection'],default=['scenarios','recovery'])
    parser.add_argument('--retain',action='store_true')
    args=parser.parse_args();run(args.docker,args.sections,args.retain)
