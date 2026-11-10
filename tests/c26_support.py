"""Owned actual HTTP/SQLite fixture; simulated deployment binding only in unit tests."""

import copy
import hmac
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.request import urlopen

from m4_support import ROOT, RuntimeWorld, Server
from security_assessment.checklist_runtime import ChecklistReview
from security_assessment.scenarios import ScenarioController, snapshot
from security_runtime.common import Blocked, canonical, digest, sha256

TABLES = {
    'account-recovery-mfa': {'accounts':['id','tenant','resets']},
    'session-revocation': {'sessions':['token','account','revoked'],'documents':['id','owner','tenant','value','reads']},
    'owner-tenant-field-operation': {'documents':['id','owner','tenant','value','reads']},
    'file-handling': {'uploads':['name','content']},
    'webhook-signature-replay': {'payments':['event','amount']},
    'idempotency-concurrency': {'balance':['id','value'],'transactions':['id','intent','owner','amount']},
    'secret-rotation': {'settings':['id','generation'],'balance':['id','value']},
    'retention-deletion': {'customers':['id','owner','data'],'copies':['id','data']},
}


class App:
    def __init__(self, root, mode):
        self.root=Path(root);self.root.mkdir();self.source=self.root/'source';self.source.mkdir()
        self.database=self.root/'application.sqlite3'
        raw=(Path(__file__).with_name('fixtures')/'c26_app.py').read_bytes().replace(b"MODE='fixed'",("MODE='"+mode+"'").encode())
        (self.source/'app.py').write_bytes(raw)
        with socket.socket() as connection:
            connection.bind(('127.0.0.1',0));port=connection.getsockname()[1]
        self.url='http://127.0.0.1:'+str(port)+'/'
        self.process=subprocess.Popen([sys.executable,'-I','-B',str(self.source/'app.py'),str(self.database),'--port',str(port)],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            try:
                with urlopen(self.url+'health',timeout=0.5):break
            except Exception:
                if self.process.poll() is not None:raise RuntimeError('owned app stopped')
                time.sleep(0.05)
        else:self.close();raise RuntimeError('owned app readiness timed out')
    def close(self):
        if self.process.poll() is None:self.process.terminate();self.process.wait(timeout=5)


class ScenarioWorld:
    def __init__(self, factory=App):
        server=Server()
        try:self.world=RuntimeWorld(server)
        finally:server.close()
        self.control=ChecklistReview(self.world.state,ROOT,upstream=self.world.publisher)
        self.control.traffic.binding_validator=self.binding
        self.bindings={};self.apps=[];self.factory=factory
    def binding(self,case,key,refresh=False):
        return copy.deepcopy(self.bindings[key])
    def add(self,key,mode):
        app=self.factory(self.world.root/key,mode);self.apps.append(app)
        spec=copy.deepcopy(self.world.spec);spec['id']=key
        spec['source'].update(root=str(app.source),files=['app.py'],revision=sha256((app.source/'app.py').read_bytes())[:40])
        spec['deployments'][0]['url']=app.url
        self.control.create(spec);case=self.control.case(key)
        self.bindings[key]={'assessment':key,'source_sha256':digest(case['source']['manifest']),'deployment':'local',
            'source_binding_verified':True,'url_binding_verified':True,'database_host_path':str(app.database),
            'test_only_binding':'simulated; actual Docker qualification is a separate gate'}
        return app,case
    def prepare(self,key,mode,family,stamp=None):
        app,case=self.add(key,mode)
        oracle={'path':str(app.database),'tables':TABLES[family]}
        before=snapshot(oracle)
        routes,cases,bodies,credentials,proofs=business_cases(family,before,app.url,stamp or int(time.time()))
        auth={'schema_version':1,'id':key,'deployment':'local','profile':'scenario','addresses':['127.0.0.1'],
            'network':'loopback','ca_sha256':None,'routes':routes,'limits':{'requests':32,'seconds':120,'response_bytes':4096,
            'total_body_bytes':262144,'timeout_seconds':3,'interval_ms':100,'concurrency':4,'expires_at':time.time()+600}}
        self.control.traffic.authorize(case,auth)
        spec={'schema_version':1,'id':key,'family':family,'authorization':key,'source_sha256':digest(case['source']['manifest']),
            'deployment_evidence':key,'oracle':oracle,'identity_proofs':proofs,'cases':cases}
        self.control.traffic.plan(case,spec)
        return case,spec,bodies,credentials
    def run(self,*args,**kwargs):
        case,spec,bodies,credentials=self.prepare(*args,**kwargs)
        errors=[]
        safe_reasons={'process deadline exceeded','cannot enforce process deadline',
            'control state is busy; inspect retained operation state before further action',
            'traffic observation unavailable; do not retry uncertain writes',
            'traffic wall-clock budget exhausted','traffic budget exhausted',
            'cannot retain bounded execution evidence','traffic collector changed',
            'live deployment changed before request','live deployment changed after request',
            'credential identity is not independently established'}
        def trace(frame,event,arg):
            if frame.f_code is not ScenarioController.exercise.__code__:return None
            frame.f_trace_lines=False
            if event=='exception' and len(errors)<8:
                kind,error,tb=arg
                frames=[]
                while tb is not None and len(frames)<8:
                    frames.append({'file':Path(tb.tb_frame.f_code.co_filename).name,
                                   'function':tb.tb_frame.f_code.co_name,'line':tb.tb_lineno})
                    tb=tb.tb_next
                reason=str(error) if type(error) is Blocked and str(error) in safe_reasons else 'unclassified; private inspection required'
                errors.append({'type':kind.__name__,'reason':reason,'frames':frames})
            return trace
        # Owned fixture diagnostics only: observe the exception swallowed by the
        # public blocked/unverified contract, without exposing locals or payloads.
        previous=sys.gettrace()
        if previous is None:sys.settrace(trace)
        try:result=self.control.traffic.exercise(case,spec['id'],bodies,credentials)
        finally:
            if previous is None:sys.settrace(None)
        if result['status']=='blocked':result['fixture_diagnostics']=errors
        return result
    def close(self):
        for app in self.apps:app.close()
        self.world.close()


def business_cases(family,before,base,stamp):
    """Independent business expectations; never derived by running a fixed app."""
    state=copy.deepcopy(before);routes=[];cases=[];bodies={};credentials={};proofs={}
    ok={'ok':True};denied={'error':'denied'}
    def step(key,kind,path,body=None,actor=None,status=200,response=None,change=None,duplicate=False):
        if change:change(state)
        selected=[]
        for suffix in ('-one','-two') if duplicate else ('',):
            name=key+suffix;raw=b'' if body is None else canonical(body)
            routes.append({'id':name,'url':base+path,'method':'GET' if body is None else 'POST',
                'credential':actor,'body_sha256':sha256(raw),'effect':'read' if body is None else 'synthetic-write'})
            if body is not None:bodies[name]=raw
            selected.append(name)
        possibilities=[response if response is not None else ok]
        if duplicate:possibilities.append({'ok':True,'replayed':True})
        cases.append({'id':key,'kind':kind,'routes':selected,'statuses':[[status] for _ in selected],
            'response_sha256':[[digest(p) for p in possibilities] for _ in selected],
            'expected_state':copy.deepcopy(state),'concurrent':duplicate})
    def change(table,column,value,identifier=None):
        def apply(state):
            for row in state[table]:
                if identifier is None or row.get('id')==identifier:row[column]=value
        return apply
    if family=='account-recovery-mfa':
        good={'account':'bob','recovery':'owned-recovery-proof','mfa':'owned-second-factor'}
        step('recovery','legitimate','account/recovery',good,change=change('accounts','resets',1,'bob'))
        step('missing-factor','prohibited','account/recovery',{**good,'mfa':''},status=403,response=denied)
        step('other-account','related-variant','account/recovery',{**good,'account':'carol'},status=403,response=denied)
    elif family=='session-revocation':
        def revoke(state):
            for row in state['sessions']:
                if row['account']=='alice':row['revoked']=1
        step('revoke','legitimate','sessions/revoke',{},'alice',change=revoke)
        step('revoked-read','prohibited','documents/read',actor='alice',status=403,response=denied)
        step('revoked-write','related-variant','documents/update',{'id':1,'value':7},'alice',403,denied)
    elif family=='owner-tenant-field-operation':
        step('owner-write','legitimate','documents/update',{'id':1,'value':7},'alice',change=change('documents','value',7,1))
        step('other-owner','prohibited','documents/update',{'id':2,'value':7},'alice',403,denied)
        step('other-tenant','related-variant','documents/update',{'id':3,'value':7},'alice',403,denied)
        step('extra-field','related-variant','documents/update',{'id':1,'value':9,'owner':'alice'},'alice',403,denied)
    elif family=='file-handling':
        step('text-upload','legitimate','files/upload',{'name':'safe.txt','content':'owned'},'alice',change=lambda s:s['uploads'].append({'name':'safe.txt','content':'owned'}))
        step('traversal','prohibited','files/upload',{'name':'../escape.txt','content':'owned'},'alice',403,denied)
        step('active-file','related-variant','files/upload',{'name':'payload.php','content':'owned'},'alice',403,denied)
        step('oversize-file','related-variant','files/upload',{'name':'large.txt','content':'x'*65},'alice',403,denied)
    elif family=='webhook-signature-replay':
        def signed(event,when):
            body={'event':event,'amount':10,'timestamp':when}
            return {**body,'signature':hmac.new(b'owned-synthetic-webhook-key',canonical(body),'sha256').hexdigest()}
        good=signed('one',stamp)
        step('signed','legitimate','webhooks/payment',good,change=lambda s:s['payments'].append({'event':'one','amount':10}))
        step('forged','prohibited','webhooks/payment',{**signed('two',stamp),'signature':'0'*64},status=403,response=denied)
        step('replay','related-variant','webhooks/payment',good,status=409,response={'error':'replay'})
        step('stale','related-variant','webhooks/payment',signed('three',stamp-600),status=403,response=denied)
    elif family=='idempotency-concurrency':
        good={'intent':'owned-one','amount':10}
        def committed(s):
            s['balance'][0]['value']=10;s['transactions'].append({'id':1,'intent':'owned-one','owner':'alice','amount':10})
        step('concurrent','legitimate','transactions/create',good,'alice',change=committed,duplicate=True)
        step('changed-amount','prohibited','transactions/create',{**good,'amount':50},'alice',422,{'error':'intent-conflict'})
        step('changed-owner','related-variant','transactions/create',good,'bob',422,{'error':'intent-conflict'})
    elif family=='secret-rotation':
        step('old-usable','legitimate','secrets/use',{},'old-key',change=change('balance','value',1))
        step('rotate','legitimate','secrets/rotate',{},'alice',change=change('settings','generation',2))
        step('old-revoked','prohibited','secrets/use',{},'old-key',403,denied)
        step('new-usable','related-variant','secrets/use',{},'new-key',change=change('balance','value',2))
    elif family=='retention-deletion':
        def deleted(number):
            def apply(s):
                for table in ('customers','copies'):s[table]=[r for r in s[table] if r['id']!=number]
            return apply
        step('delete-own','legitimate','customers/delete',{'id':1},'alice',change=deleted(1))
        step('delete-other','prohibited','customers/delete',{'id':2},'alice',403,denied)
        step('other-owner-delete','related-variant','customers/delete',{'id':2},'carol',change=deleted(2))
    else:raise ValueError('unknown family')
    for actor in sorted({r['credential'] for r in routes}-{None}):
        token='owned-'+actor if actor.endswith('-key') else actor+'-session'
        credentials[actor]={'header':'Authorization','value':'Bearer '+token}
        name='identity-'+actor
        routes.append({'id':name,'url':base+'identity','method':'GET','credential':actor,'body_sha256':sha256(b''),'effect':'read'})
        identity={'principal':'integration'} if actor.endswith('-key') else {'account':actor,'tenant':'two' if actor=='carol' else 'one'}
        proofs[actor]={'route':name,'body_sha256':digest(identity)}
    return routes,cases,bodies,credentials,proofs
