from contextlib import closing
import copy
import hmac
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch
from urllib.request import Request,build_opener,ProxyHandler,urlopen

from c26_support import ScenarioWorld
from m4_support import ROOT,RuntimeWorld,Server
from security_assessment.checklist_runtime import ChecklistReview
from security_runtime.common import Blocked,canonical,digest,sha256
from security_runtime.detection import DetectionListeners


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.server=Server();self.addCleanup(self.server.close)
        self.world=RuntimeWorld(self.server);self.addCleanup(self.world.close)
        self.control=ChecklistReview(self.world.state,ROOT,upstream=self.world.publisher)
        spec=copy.deepcopy(self.world.spec);spec['id']='detection';self.control.create(spec)
        self.case=self.control.case('detection')
        self.control.traffic.binding_validator=lambda case,key,refresh=False:{'source_binding_verified':True,'url_binding_verified':True,'deployment':'local','test_only_binding':'simulated'}
    def exercise(self,forward=True,forge=False):
        recovery=self.control.service_recovery
        recovery.plan_detection(self.case,{'id':'owned','event':'audit-test','hops':['target','collector','receiver'],'owner':'Owned test operator','timeout_seconds':60,'application_binding':'target','target_path':'/audit-exercise'})
        store=self.world.state;record=store.get('detection-exercise','owned')
        listener=DetectionListeners(store,'owned',lambda:None);url=listener.start();self.addCleanup(listener.close)
        target_path=self.world.root/'target.jsonl';expected=record['expected']
        # The owned target receives only its own key and actual collector address.
        target_key=bytes.fromhex(record['keys']['target']);calls=[]
        def post(handler):
            body=handler.rfile.read(int(handler.headers['Content-Length']));calls.append(body)
            if sha256(body)!=expected['event_sha256']:raise RuntimeError('wrong synthetic trigger')
            value={'exercise':'owned','event':'audit-test','hop':'target','previous_sha256':expected['event_sha256'],
                'observed_at':time.time(),'owner':expected['owner']}
            row={**value,'mac':hmac.new(target_key,canonical(value),'sha256').hexdigest()}
            target_path.write_bytes(canonical(row)+b'\n')
            if forward:
                opener=build_opener(ProxyHandler({}))
                with opener.open(Request(url,data=canonical([row]),headers={'Content-Type':'application/json'},method='POST'),timeout=3) as response:
                    if response.status!=204:raise RuntimeError('actual collector failed')
            response=canonical({'audit_event':row})
            handler.send_response(200);handler.send_header('Content-Length',str(len(response)));handler.end_headers();handler.wfile.write(response)
        self.server.http.RequestHandlerClass.do_POST=post
        event=canonical(record['event'])
        self.control.traffic.authorize(self.case,{'schema_version':1,'id':'trigger','deployment':'local','profile':'scenario',
            'addresses':['127.0.0.1'],'network':'loopback','ca_sha256':None,'routes':[{'id':'event','url':self.server.url+'audit-exercise',
            'method':'POST','credential':None,'body_sha256':sha256(event),'effect':'synthetic-write'}],
            'limits':{'requests':1,'seconds':10,'response_bytes':1024,'total_body_bytes':8192,'timeout_seconds':3,'interval_ms':100,'concurrency':1,'expires_at':time.time()+60}})
        trigger=self.control.traffic.execute(self.case,'trigger','event',event)['operation']
        self.assertEqual(calls,[event])
        paths={'target':str(target_path)}
        previous=digest(json.loads(target_path.read_bytes()))
        for hop in ('collector','receiver'):
            path=store.root/('detection-owned-'+hop+'.jsonl');paths[hop]=str(path)
            if forge:
                value={'exercise':'owned','event':'audit-test','hop':hop,'previous_sha256':previous,'observed_at':time.time(),'owner':expected['owner']}
                row={**value,'mac':hmac.new(bytes.fromhex(record['keys'][hop]),canonical(value),'sha256').hexdigest()}
                path.write_bytes(canonical(row)+b'\n');previous=digest(row)
            elif not path.exists():path.write_bytes(b'')
        return recovery.detection(self.case,'owned',paths,trigger)
    def test_actual_target_collector_receiver_transport(self):
        result=self.exercise();self.assertEqual(result['outcome'],'satisfied')
        self.assertEqual(len(result['hops']),3)
    def test_missing_hops_and_assessor_constructed_signed_logs_cannot_pass(self):
        self.assertEqual(self.exercise(forward=False,forge=True)['outcome'],'failed')
    def test_untriggered_event_never_creates_transport_receipts(self):
        self.control.service_recovery.plan_detection(self.case,{'id':'no-event','event':'audit-test','hops':['target','collector','receiver'],'owner':'Owned operator','timeout_seconds':1,'application_binding':'target','target_path':'/audit-exercise'})
        listeners=DetectionListeners(self.world.state,'no-event',lambda:None);listeners.start()
        with self.assertRaises(Blocked):listeners.wait()
        self.assertIsNone(self.world.state.get('detection-hop','no-event-receiver'))


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.world=ScenarioWorld();self.addCleanup(self.world.close)
        self.app,self.initial=self.world.add('source','fixed')
        self.control=self.world.control;self.store=self.world.world.state
        with socket.socket() as conn:conn.bind(('127.0.0.1',0));self.port=conn.getsockname()[1]
        self.restored_url='http://127.0.0.1:'+str(self.port)+'/'
        spec=copy.deepcopy(self.initial['scope']);spec['id']='recovery'
        spec['deployments'].append({'id':'restored','environment':'local','url':self.restored_url,'artifact':spec['deployments'][0]['artifact']})
        self.control.create(spec);self.case=self.control.case('recovery')
        self.world.bindings['source'].update(assessment='recovery',container='owned-original')
        self.credentials={'old':{'header':'Authorization','value':'Bearer recovery-old'},'new':{'header':'Authorization','value':'Bearer recovery-new'},
            'admin':{'header':'Authorization','value':'Bearer alice-session'}}
        self.prior=self.request('prior','local','old')
    def request(self,key,deployment,actor,body=None,path='state'):
        base=self.app.url if deployment=='local' else self.restored_url
        raw=b'' if body is None else canonical(body)
        # Completed evidence must remain valid across the multi-step restore.
        # The actual request deadline and the recovery deadline stay separate.
        self.control.traffic.authorize(self.case,{'schema_version':1,'id':key,'deployment':deployment,'profile':'scenario',
            'addresses':['127.0.0.1'],'network':'loopback','ca_sha256':None,'routes':[{'id':key,'url':base+path,'method':'GET' if body is None else 'POST',
            'credential':actor,'body_sha256':sha256(raw),'effect':'read' if body is None else 'synthetic-write'}],
            'limits':{'requests':1,'seconds':60,'response_bytes':4096,'total_body_bytes':8192,'timeout_seconds':3,'interval_ms':100,'concurrency':1,'expires_at':time.time()+120}})
        return self.control.traffic.execute(self.case,key,key,raw,self.credentials)['operation']
    def capture(self,max_loss=1):
        spec={'id':'restore','application_binding':'source','oracle':{'path':str(self.app.database),'tables':{'events':['id','data']}},
            'watermark_table':'events','watermark_column':'id','max_loss_events':max_loss,'max_recovery_seconds':60,
            'service_expectation':{'body_sha256':digest({'events':[[1,'synthetic-first']]}),'denial_body_sha256':digest({'error':'denied'}),
            'allowed_credential':'new','compromised_credential':'old','compromised_prior_operation':self.prior,'deployment':'restored'}}
        self.control.service_recovery.capture(self.case,spec)
        with closing(sqlite3.connect(self.app.database)) as db,db:db.execute('INSERT INTO events VALUES (2,"committed-after-backup")')
    def restore(self,rotate=True,exposed=False):
        result=self.control.service_recovery.restore(self.case,'restore');restored=Path(result['restored_path'])
        process=subprocess.Popen([sys.executable,'-I','-B',str(self.app.source/'app.py'),str(restored),'--port',str(self.port)],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        def stop():process.terminate();process.wait(5)
        self.addCleanup(stop)
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            try:
                with urlopen(self.restored_url+'health',timeout=.5):break
            except Exception:time.sleep(.05)
        binding={**self.world.bindings['source'],'database_host_path':str(restored),'deployment':'restored','container':'owned-restored'}
        self.world.bindings['restored']=binding
        if rotate:self.request('rotate','restored','admin',{},'secrets/rotate')
        positive=self.request('positive','restored','new');negative=self.request('negative','restored','old')
        # Unit-only substitute. Actual compromised UID access is a separate Docker gate.
        def probe(assessment,recovery,identity):
            record=self.store.get('service-recovery',recovery)
            with self.store.transaction() as tx:
                tx.put('backup-access-operation','owned-proof',{'assessment':assessment,'backup_sha256':record['backup_sha256'],
                    'binding':identity,'binding_sha256':digest(binding),'container':binding['container'],'read_succeeded':exposed})
            return {'operation':'owned-proof'}
        self.control.service_recovery.backup_probe=probe;probe('recovery','restore','restored')
        return positive,negative
    def test_real_database_restore_service_and_formerly_valid_access_revocation(self):
        self.capture();positive,negative=self.restore()
        result=self.control.service_recovery.finish(self.case,'restore',positive,negative,'owned-proof','restored')
        self.assertEqual(result['outcome'],'satisfied',result);self.assertEqual(result['measured_lost_committed_events'],1)
        self.assertTrue(self.app.database.exists())
    def test_retained_compromised_access_and_excess_loss_fail(self):
        self.capture(max_loss=0);positive,negative=self.restore(rotate=False,exposed=True)
        result=self.control.service_recovery.finish(self.case,'restore',positive,negative,'owned-proof','restored')
        self.assertEqual(result['outcome'],'failed')
        for check in ('compromised_access_revoked','loss_within_budget','backup_isolated'):self.assertFalse(result['checks'][check])
    def test_unrelated_access_proof_and_random_invalid_old_token_are_rejected(self):
        self.capture();positive,negative=self.restore()
        with self.store.transaction() as tx:
            proof=tx.get('backup-access-operation','owned-proof');proof['binding']='different';tx.put('backup-access-operation','owned-proof',proof)
        with self.assertRaises(Blocked):self.control.service_recovery.finish(self.case,'restore',positive,negative,'owned-proof','restored')
        self.credentials['old']['value']='Bearer never-valid'
        wrong=self.request('random-token','restored','old')
        with self.assertRaises(Blocked):self.control.service_recovery.finish(self.case,'restore',positive,wrong,'owned-proof','restored')
    def test_corrupted_backup_cannot_restore(self):
        self.capture();record=self.store.get('service-recovery','restore')
        (self.store.root/record['backup']).write_bytes(b'corrupted')
        with self.assertRaises(Blocked):self.control.service_recovery.restore(self.case,'restore')
        self.assertEqual(self.store.get('service-recovery','restore')['status'],'captured')

    def test_wrong_restored_state_and_elapsed_budget_cannot_pass(self):
        self.capture();positive,negative=self.restore()
        record=self.store.get('service-recovery','restore')
        with closing(sqlite3.connect(self.store.root/record['restored'])) as db,db:
            db.execute('UPDATE events SET data="incorrect-restored-value" WHERE id=1')
        service=self.control.service_recovery;service.clock=lambda:time.time()+61
        result=service.finish(self.case,'restore',positive,negative,'owned-proof','restored')
        self.assertEqual(result['outcome'],'failed')
        self.assertFalse(result['checks']['restored_state']);self.assertFalse(result['checks']['recovery_within_budget'])
        self.assertGreater(result['measured_service_recovery_seconds'],60)
        self.assertTrue(all(value for key,value in result['checks'].items()
                            if key not in {'restored_state','recovery_within_budget'}))

    def test_expired_prior_authority_blocks_recovery_without_effects(self):
        self.capture();positive,negative=self.restore()
        service=self.control.service_recovery;traffic=self.control.traffic
        record=self.store.get('service-recovery','restore')
        protected=[('service-recovery','restore'),('backup-access-operation','owned-proof')]
        for key in ('prior','rotate','positive','negative'):
            authority=self.store.get('traffic-authority',key)
            protected.append(('traffic-authority',key))
            protected.extend(('traffic-operation',operation) for operation in authority['intents'].values())
        before={pair:self.store.get(*pair) for pair in protected}
        files={name:(self.store.root/record[name]).read_bytes() for name in ('backup','restored')}
        prior=self.store.get('traffic-authority','prior')
        traffic.clock=lambda:prior['first_request_at']+prior['spec']['limits']['seconds']
        with patch.object(service,'backup_probe',side_effect=AssertionError('unexpected backup probe')), \
                patch.object(traffic,'_request',side_effect=AssertionError('unexpected request')):
            with self.assertRaisesRegex(Blocked,'traffic wall-clock budget exhausted'):
                service.finish(self.case,'restore',positive,negative,'owned-proof','restored')
        self.assertEqual({pair:self.store.get(*pair) for pair in protected},before)
        self.assertEqual({name:(self.store.root/record[name]).read_bytes() for name in files},files)
        self.assertEqual(self.store.get('service-recovery','restore')['status'],'restored-awaiting-service')


if __name__=='__main__':unittest.main()
