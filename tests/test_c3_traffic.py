import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

from m4_support import ROOT,RuntimeWorld,Server
from security_runtime.common import Blocked,sha256
from security_runtime.traffic import TrafficController


class TrafficTests(unittest.TestCase):
    def setUp(self):
        self.server=Server();self.addCleanup(self.server.close)
        self.world=RuntimeWorld(self.server);self.addCleanup(self.world.close)
        self.control=TrafficController(self.world.state,ROOT,self.world.publisher,clock=lambda:self.world.now[0])
        self.case=self.world.state.get('assessment','demo')
        # Assessment records are loaded through their existing contract.
        with self.world.state.transaction() as tx:self.case=self.world.control._case(tx,'demo')
    def route(self,key,path='',credential=None):
        return {'id':key,'url':self.server.url+path,'method':'GET','credential':credential,'body_sha256':sha256(b''),'effect':'read'}
    def spec(self,routes=None,key='capture',**limits):
        value={'schema_version':1,'id':key,'deployment':'local','profile':'capture','addresses':['127.0.0.1'],'network':'loopback','ca_sha256':None,
            'routes':routes or [self.route('start')],'limits':{'requests':8,'seconds':24,'response_bytes':4096,'total_body_bytes':32768,'timeout_seconds':3,'interval_ms':100,'concurrency':1,'expires_at':self.world.now[0]+120}}
        value['limits'].update(limits);return value
    def test_legitimate_navigation_and_private_capture(self):
        self.server.handler=lambda path,token:(200,{'Content-Type':'text/html'},b'<a href="/next">next</a>') if path=='/' else (200,{},b'private-owned-fixture')
        self.control.authorize(self.case,self.spec([self.route('start'),self.route('next','next')],concurrency=2))
        result=self.control.navigate(self.case,'capture','start')
        self.assertEqual([r['path'] for r in self.server.calls],['/','/next'])
        self.assertEqual(len(result['operations']),2);self.assertFalse(result['browser_execution'])
        self.assertNotIn('private-owned-fixture',str(result))
    def test_redirect_and_subresources_do_not_create_authority(self):
        outside=Server();self.addCleanup(outside.close)
        for index,body in enumerate((b'<img src="'+outside.url.encode()+b'"><script src="/unapproved"></script>',b'')):
            self.server.handler=lambda p,t:(302,{'Location':outside.url},body) if index else (200,{'Content-Type':'text/html'},body)
            key='capture-'+str(index);self.control.authorize(self.case,self.spec(key=key))
            result=self.control.navigate(self.case,key,'start')
            self.assertTrue(result['blocked']);self.assertEqual(outside.calls,[])
        self.assertEqual([r['path'] for r in self.server.calls],['/','/'])
    def test_methods_credentials_and_budget_reject_before_request(self):
        value=self.spec();value['routes'][0]['method']='POST'
        with self.assertRaises(Blocked):self.control.authorize(self.case,value)
        self.assertEqual(self.server.calls,[])
        value=self.spec([self.route('start'),self.route('next','next')],requests=1)
        self.control.authorize(self.case,value);self.control.execute(self.case,'capture','start')
        with self.assertRaises(Blocked):self.control.execute(self.case,'capture','next')
        with self.assertRaises(Blocked):self.control.execute(self.case,'capture','start')
        self.assertEqual(len(self.server.calls),1)
        self.control.cancel('capture')
        with self.assertRaises(Blocked):self.control.execute(self.case,'capture','next')
    def test_unexpected_authentication_destination_is_never_followed(self):
        self.server.handler=lambda p,t:(302,{'Location':'/login'},b'')
        self.control.authorize(self.case,self.spec([self.route('start',credential='owner'),self.route('login','login')]))
        result=self.control.navigate(self.case,'capture','start',credentials={'owner':{'header':'Authorization','value':'Bearer synthetic-owner'}})
        self.assertTrue(result['blocked']);self.assertEqual([r['path'] for r in self.server.calls],['/'])
    def test_source_or_authority_change_prevents_request(self):
        self.control.authorize(self.case,self.spec())
        self.world.now[0]+=121
        with self.assertRaises(Blocked):self.control.execute(self.case,'capture','start')
        self.assertEqual(self.server.calls,[])

    def test_deployment_parent_path_is_preserved(self):
        case=copy.deepcopy(self.case);case['scope']['deployments'][0]['url']=self.server.url+'app/'
        with self.assertRaises(Blocked):self.control.authorize(case,self.spec([self.route('outside','admin')]))
        self.control.authorize(case,self.spec([self.route('inside','app/record')]))
        self.control.execute(case,'capture','inside')
        self.assertEqual([r['path'] for r in self.server.calls],['/app/record'])

    def test_large_admitted_request_reaches_owned_server_exactly_once(self):
        received=[]
        def post(handler):
            received.append(handler.rfile.read(int(handler.headers['Content-Length'])))
            handler.send_response(200);handler.send_header('Content-Length','2');handler.end_headers();handler.wfile.write(b'ok')
        self.server.http.RequestHandlerClass.do_POST=post
        body=b'x'*65536;route=self.route('write');route.update(method='POST',body_sha256=sha256(body),effect='synthetic-write')
        spec=self.spec([route],total_body_bytes=131072);spec['profile']='scenario'
        self.control.authorize(self.case,spec)
        self.assertEqual(self.control.execute(self.case,'capture','write',body)['response_status'],200)
        self.assertEqual(received,[body])
        with self.assertRaises(Blocked):self.control.execute(self.case,'capture','write',body)

    def test_controller_death_between_input_flush_and_eof_sends_no_request(self):
        # The exact scheduling window of the independently reproduced orphan bug.
        ready=self.world.root/'parent-ready';script=self.world.root/'parent.py'
        payload={'url':self.server.url,'method':'GET','addresses':['127.0.0.1'],'network':'loopback','timeout':3,
            'limit':128,'credential':None,'ca':None,'body':''}
        code='''import json,os,pathlib,subprocess,sys,time
sys.path.insert(0,sys.argv[1])
from security_runtime.parent_guard import attach_windows
payload=json.loads(sys.argv[3]);payload['parent_pid']=os.getpid()
child=subprocess.Popen([sys.executable,'-I','-B',sys.argv[2]],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
binding=attach_windows(child)
child.stdin.write(json.dumps(payload).encode());child.stdin.flush()
pathlib.Path(sys.argv[4]).write_text(str(child.pid))
time.sleep(10)
'''
        script.write_text(code,encoding='utf-8')
        parent=subprocess.Popen([sys.executable,'-I','-B',str(script),str(ROOT/'scripts'),str(ROOT/'scripts/security_runtime/traffic_worker.py'),json.dumps(payload),str(ready)],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            deadline=time.monotonic()+5
            while not ready.exists() and time.monotonic()<deadline:time.sleep(.05)
            self.assertTrue(ready.exists());self.assertEqual(self.server.calls,[])
            parent.kill();parent.wait(5);time.sleep(.75)
            self.assertEqual(self.server.calls,[])
        finally:
            if parent.poll() is None:parent.kill();parent.wait(5)


if __name__=='__main__':unittest.main()
