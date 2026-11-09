"""Owned loopback collector/receiver exercise. No external notifications."""

import hmac
from http.server import BaseHTTPRequestHandler,HTTPServer
import secrets
import threading
import time
from urllib import request

from .common import canonical,digest,fields,parse,require
from .sources import NoRedirect


def check_hop(row,hop,previous,expected,key):
    fields(row,{'exercise','event','hop','previous_sha256','observed_at','owner','mac'})
    payload={k:v for k,v in row.items() if k!='mac'}
    require(row['exercise']==expected['exercise'] and row['event']==expected['event'] and row['hop']==hop
        and row['previous_sha256']==previous and row['owner']==expected['owner'] and expected['started_at']<=row['observed_at']<=expected['deadline']
        and isinstance(row['mac'],str) and hmac.compare_digest(row['mac'],hmac.new(key,canonical(payload),'sha256').hexdigest()),'unrelated or forged instrumented hop')


class DetectionListeners:
    """Two separate actual HTTP hops; only their handlers create transport receipts."""
    def __init__(self,store,exercise,guard,clock=time.time):
        self.store,self.exercise,self.guard,self.clock=store,exercise,guard,clock
        self.servers=[];self.threads=[];self.stopped=threading.Event();self.failed=threading.Event();self.calls=0;self.lock=threading.Lock()
        record=store.get('detection-exercise',exercise)
        require(record and record['status']=='planned' and record['expected']['hops']==['target','collector','receiver'],'supported instrumented three-hop plan required')
        self.expected=record['expected'];self.keys={h:bytes.fromhex(k) for h,k in record['keys'].items()}
        self.listener='listener-'+secrets.token_hex(16)

    def signed(self,hop,previous):
        value={'exercise':self.exercise,'event':self.expected['event'],'hop':hop,'previous_sha256':previous,'observed_at':self.clock(),'owner':self.expected['owner']}
        return {**value,'mac':hmac.new(self.keys[hop],canonical(value),'sha256').hexdigest()}

    def start(self):
        self.guard()
        owner=self
        class Server(HTTPServer):
            def get_request(self):
                connection,address=super().get_request();connection.settimeout(2);return connection,address
        def handler(hop):
            class Handler(BaseHTTPRequestHandler):
                def log_message(self,*args):pass
                def do_POST(self):
                    try:
                        owner.guard()
                        active=owner.store.get('detection-exercise',owner.exercise)
                        require(active['status']=='listening' and active['listener']==owner.listener,'listener no longer active')
                        require(owner.clock()<=owner.expected['deadline'] and self.path=='/hop','listener expired or route differs')
                        with owner.lock:
                            owner.calls+=1;require(owner.calls<=10,'listener request budget exhausted')
                        length=self.headers.get('Content-Length','')
                        require(length.isdecimal() and 0<int(length)<=16384 and not self.headers.get('Transfer-Encoding'),'invalid exercise request framing')
                        raw=self.rfile.read(int(length));require(len(raw)==int(length),'incomplete exercise message')
                        chain=parse(raw,16384)
                        require(isinstance(chain,list) and len(chain)==(1 if hop=='collector' else 2),'invalid transport chain')
                        previous=owner.expected['event_sha256']
                        for item,name in zip(chain,['target','collector']):
                            check_hop(item,name,previous,owner.expected,owner.keys[name]);previous=digest(item)
                        row=owner.signed(hop,previous)
                        with owner.store.transaction() as tx:
                            active=tx.get('detection-exercise',owner.exercise)
                            require(active['status']=='listening' and active['listener']==owner.listener,'listener changed during request')
                            require(tx.get('detection-hop',owner.exercise+'-'+hop) is None,'hop intent already consumed')
                            tx.put('detection-hop',owner.exercise+'-'+hop,{'listener':owner.listener,'row':row,'received_sha256':digest(chain),'received_at':owner.clock(),
                                'transport':'actual-owned-loopback-http','source_address':self.client_address[0]})
                        path=owner.store.root/('detection-'+owner.exercise+'-'+hop+'.jsonl')
                        with path.open('xb') as output:output.write(canonical(row)+b'\n')
                        if hop=='collector':
                            opener=request.build_opener(request.ProxyHandler({}),NoRedirect())
                            destination='http://127.0.0.1:'+str(owner.servers[0].server_port)+'/hop'
                            with opener.open(request.Request(destination,data=canonical(chain+[row]),headers={'Content-Type':'application/json'},method='POST'),timeout=2) as response:
                                require(response.status==204,'receiver did not acknowledge actual transport')
                        else:owner.stopped.set()
                        self.send_response(204);self.send_header('Content-Length','0');self.end_headers()
                    except Exception:
                        owner.failed.set();owner.stopped.set()
                        with owner.store.transaction() as tx:
                            active=tx.get('detection-exercise',owner.exercise)
                            if active and active.get('listener')==owner.listener and active['status']=='listening':
                                active['status']='transport-failed';tx.put('detection-exercise',owner.exercise,active)
                        self.send_response(400);self.send_header('Content-Length','0');self.end_headers()
            return Handler
        for hop in ('receiver','collector'):
            server=Server(('127.0.0.1',0),handler(hop));self.servers.append(server)
            thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':0.05},daemon=True);thread.start();self.threads.append(thread)
        with self.store.transaction() as tx:
            record=tx.get('detection-exercise',self.exercise)
            require(record['status']=='planned','listener plan changed')
            record.update(status='listening',listener=self.listener,collector_url='http://127.0.0.1:'+str(self.servers[1].server_port)+'/hop')
            tx.put('detection-exercise',self.exercise,record)
        return record['collector_url']

    def wait(self):
        try:
            while not self.stopped.wait(0.1):
                self.guard();require(self.clock()<=self.expected['deadline'],'instrumented transport deadline exceeded')
            require(not self.failed.is_set(),'instrumented transport failed')
            return {'status':'collected','exercise':self.exercise}
        finally:self.close()

    def close(self):
        self.stopped.set()
        for server in self.servers:server.shutdown();server.server_close()
        for thread in self.threads:thread.join(2)
        self.servers=[];self.threads=[]
