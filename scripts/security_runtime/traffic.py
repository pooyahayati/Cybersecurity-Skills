"""Versioned traffic authority, separate from M1 offline and M4 read contracts."""

import base64
import copy
import hmac
import os
from pathlib import Path
import secrets
import sys
import time
from html.parser import HTMLParser
from urllib.parse import urljoin

from .common import canonical, digest, fields, identifier, integer, number, parse, require, sha256
from .controller import HEAD_RESOURCES, selected_tree
from .process import bounded_process
from .web import WebController
from .web_scope import address, credential, fingerprint, url

# Base64 of the largest body, worst-case JSON escapes for bounded Latin-1
# header text, and fixed framing/address/hash metadata. This is not a wire cap.
CAPTURE_OUTPUT_LIMIT=((262144+2)//3)*4+32768*6+16384

def authority(spec, deployment, now):
    fields(spec, {'schema_version','id','deployment','profile','addresses','network','routes','limits','ca_sha256'})
    require(spec['schema_version'] == 1 and spec['profile'] in {'capture','scenario'}, 'unsupported traffic authority')
    identifier(spec['id'])
    require(spec['deployment'] == deployment['id'], 'deployment differs')
    origin = url(deployment['url'])[:3]
    require(spec['network'] in {'loopback','private','public'} and (origin[0]=='https' or
            spec['network']=='loopback' and deployment['environment']=='local'), 'unsupported network class')
    require(isinstance(spec['addresses'], list) and 0 < len(spec['addresses']) <= 8 and len(set(spec['addresses']))==len(spec['addresses']), 'invalid address pins')
    for item in spec['addresses']: address(item, spec['network'])
    fingerprint(spec['ca_sha256'], nullable=True)
    limits = spec['limits']
    fields(limits, {'requests','seconds','response_bytes','total_body_bytes','timeout_seconds','interval_ms','concurrency','expires_at'})
    integer(limits['requests'],1,256)
    integer(limits['seconds'],1,1200)
    integer(limits['response_bytes'],1,262144)
    integer(limits['total_body_bytes'],1,16*1024**2)
    integer(limits['timeout_seconds'],1,min(15,limits['seconds']))
    integer(limits['interval_ms'],100,60000)
    integer(limits['concurrency'],1,4)
    number(limits['expires_at'],now+1,now+3600)
    require(isinstance(spec['routes'],list) and 0 < len(spec['routes']) <= 128, 'invalid route selection')
    seen = set()
    for row in spec['routes']:
        fields(row, {'id','url','method','credential','body_sha256','effect'})
        identifier(row['id'])
        require(row['id'] not in seen, 'duplicate route')
        seen.add(row['id'])
        parsed=url(row['url']);base=url(deployment['url'])[3]
        require(parsed[:3] == origin and (base=='/' or parsed[3]==base or parsed[3].startswith(base.rstrip('/')+'/')), 'route leaves authorized deployment')
        methods = {'GET','HEAD'} if spec['profile']=='capture' else {'GET','HEAD','POST','PUT','PATCH','DELETE'}
        require(row['method'] in methods, 'method outside profile')
        require(row['effect'] in {'read','synthetic-write'} and (row['method'] not in {'GET','HEAD'} or row['effect']=='read'), 'effect declaration differs')
        require(row['method'] in {'GET','HEAD'} or row['effect']=='synthetic-write', 'write effect authority required')
        fingerprint(row['body_sha256'])
        require(row['method'] not in {'GET','HEAD'} or row['body_sha256']==sha256(b''), 'read body unsupported')
        if row['credential'] is not None: identifier(row['credential'])


class TrafficController(WebController):
    def authorize(self, case, value):
        deployment = next((d for d in case['scope']['deployments'] if d['id']==value.get('deployment')), None)
        require(deployment is not None, 'deployment unavailable')
        authority(value, deployment, self.clock())
        head = self.fresh_head()
        record = {'spec':copy.deepcopy(value),'assessment':case['scope']['id'],'scope_sha256':case['scope_sha256'],
                  'head':head,'revoked':False,'intents':{},'requests_used':0,'seconds_used':0,'bytes_reserved':0,
                  'active':0,'last_reserved':self.clock(),'tokens':value['limits']['concurrency'],'first_request_at':None,'created_at':self.clock()}
        with self.store.transaction() as tx:
            require(tx.get('traffic-authority',value['id']) is None, 'authority ID cannot be reused')
            tx.put('traffic-authority',value['id'],record)
        return {'authorization':value['id'],'status':'authorized','security_verdict':'not_established'}

    def guard(self, key, case=None, tx=None):
        store = tx or self.store
        record = store.get('traffic-authority',key)
        require(record and not record['revoked'] and self.clock()<record['spec']['limits']['expires_at'], 'traffic authority unavailable')
        require(record['first_request_at'] is None or self.clock()<record['first_request_at']+record['spec']['limits']['seconds'],'traffic wall-clock budget exhausted')
        if case is not None:
            require(case['scope']['id']==record['assessment'] and case['scope_sha256']==record['scope_sha256'], 'assessment scope changed')
        head = store.get('candidate',record['head']['candidate'])
        require(head and digest(head)==record['head']['record_sha256'], 'head producer changed')
        self.controller.reviewed(record['head']['candidate'],head,store)
        require(selected_tree(self.package,HEAD_RESOURCES)==record['head']['manifest'], 'traffic collector changed')
        return record

    def cancel(self,key):
        with self.store.transaction() as tx:
            value = tx.get('traffic-authority',key)
            require(value is not None,'authority unavailable')
            value['revoked'] = True
            tx.put('traffic-authority',key,value)
        return {'status':'cancelled'}

    def _request(self,payload,guard):
        env = {'PATH':os.defpath}
        if os.name=='nt':
            for name in ('SYSTEMROOT','WINDIR','TEMP','TMP'):
                if name in os.environ: env[name]=os.environ[name]
        result = bounded_process([sys.executable,'-I','-B',str(Path(__file__).with_name('traffic_worker.py'))],env,
            payload['timeout'],CAPTURE_OUTPUT_LIMIT,guard=guard,input_data=canonical(payload),max_input_bytes=110000,kill_with_parent=True)
        require(result['exit_code']==0,'traffic observation unavailable; do not retry uncertain writes')
        output = parse(result['content'],CAPTURE_OUTPUT_LIMIT)
        fields(output,{'schema_version','status','headers','body','body_bytes','body_sha256','address'})
        require(output['schema_version']==1,'unsupported traffic output')
        raw=base64.b64decode(output['body'],validate=True)
        require(len(raw)==output['body_bytes']<=payload['limit'] and sha256(raw)==output['body_sha256'],'capture integrity failed')
        return output

    def execute(self,case,key,route_id,body=b'',credentials=None,ca=None):
        auth=self.guard(key,case)
        route=next((r for r in auth['spec']['routes'] if r['id']==route_id),None)
        require(route and isinstance(body,bytes) and len(body)<=65536 and sha256(body)==route['body_sha256'],'request differs from authorized bytes')
        require((ca is None and auth['spec']['ca_sha256'] is None) or isinstance(ca,str) and sha256(ca.encode('ascii'))==auth['spec']['ca_sha256'],'CA differs')
        supplied=None
        if route['credential'] is not None:
            require(isinstance(credentials,dict) and route['credential'] in credentials,'credential unavailable')
            supplied=credentials[route['credential']]
            credential(supplied)
        self.fresh_head()  # Fresh failure cannot reuse prior currentness.
        operation='traffic-'+secrets.token_hex(16)
        limits=auth['spec']['limits']
        with self.store.transaction() as tx:
            auth=self.guard(key,case,tx)
            tokens=min(limits['concurrency'],auth['tokens']+(self.clock()-auth['last_reserved'])/(limits['interval_ms']/1000))
            require(route_id not in auth['intents'],'single-use intent consumed')
            require(auth['requests_used']<limits['requests'] and auth['seconds_used']+limits['timeout_seconds']<=limits['seconds']
                and auth['bytes_reserved']+limits['response_bytes']+len(body)<=limits['total_body_bytes']
                and auth['active']<limits['concurrency'] and tokens>=1,'traffic budget exhausted')
            auth['requests_used']+=1; auth['seconds_used']+=limits['timeout_seconds']
            auth['bytes_reserved']+=limits['response_bytes']+len(body); auth['active']+=1
            auth['tokens']=tokens-1
            auth['last_reserved']=self.clock(); auth['intents'][route_id]=operation
            if auth['first_request_at'] is None: auth['first_request_at']=self.clock()
            tx.put('traffic-authority',key,auth)
            tx.put('traffic-operation',operation,{'authorization':key,'authority_sha256':digest(auth['spec']),'route':route_id,
                'credential_binding':hmac.new(self.store.key,canonical(supplied),'sha256').hexdigest(),
                'status':'unfinished','started_at':self.clock(),'result':None})
        try:
            payload={'url':route['url'],'method':route['method'],'addresses':auth['spec']['addresses'],'network':auth['spec']['network'],
                'timeout':limits['timeout_seconds'],'limit':limits['response_bytes'],'credential':supplied,'ca':ca,'body':base64.b64encode(body).decode(),'parent_pid':os.getpid()}
            result=self._request(payload,lambda:self.guard(key,case))
            with self.store.transaction() as tx:
                self.guard(key,case,tx)
                record=tx.get('traffic-operation',operation)
                record.update(status='completed',result=result,finished_at=self.clock())
                tx.put('traffic-operation',operation,record)
            return {'operation':operation,'status':'completed','response_status':result['status'],'security_verdict':'not_established'}
        except Exception:
            with self.store.transaction() as tx:
                record=tx.get('traffic-operation',operation)
                record.update(status='uncertain',finished_at=self.clock())
                tx.put('traffic-operation',operation,record)
            raise
        finally:
            with self.store.transaction() as tx:
                auth=tx.get('traffic-authority',key); auth['active']-=1
                tx.put('traffic-authority',key,auth)

    def observe(self,case,operation):
        record=self.store.get('traffic-operation',operation)
        require(record and record['status']=='completed','completed traffic observation required')
        auth=self.guard(record['authorization'],case)
        require(record['authority_sha256']==digest(auth['spec']) and auth['intents'].get(record['route'])==operation,'traffic producer differs')
        return record,auth

    def navigate(self,case,key,start,credentials=None,ca=None):
        auth=self.guard(key,case)
        require(auth['spec']['profile']=='capture','navigation requires capture profile')
        routes={r['id']:r for r in auth['spec']['routes']}
        require(start in routes,'start route unavailable')
        queue,visited,observations,blocked=[start],set(),[],[]
        while queue:
            route_id=queue.pop(0)
            if route_id in visited: continue
            visited.add(route_id)
            result=self.execute(case,key,route_id,credentials=credentials,ca=ca)
            observations.append(result['operation'])
            record,_=self.observe(case,result['operation'])
            response=record['result']; links=[]
            if 300<=response['status']<400:
                links=[v for k,v in response['headers'] if k.lower()=='location']
            else:
                class Links(HTMLParser):
                    def handle_starttag(self,tag,attrs):
                        for k,v in attrs:
                            if v and (tag=='a' and k=='href' or tag in {'img','script','iframe','source'} and k=='src' or tag=='link' and k=='href'): links.append(v)
                if any(k.lower()=='content-type' and 'text/html' in v.lower() for k,v in response['headers']):
                    Links().feed(base64.b64decode(response['body']).decode('utf-8','replace'))
            require(len(links)<=256,'navigation links exceed limit')
            for link in links:
                destination=urljoin(routes[route_id]['url'],link)
                matches=[r['id'] for r in routes.values() if r['url']==destination and r['method']=='GET'
                    and r['credential']==routes[route_id]['credential']]
                if len(matches)==1: queue.append(matches[0])
                else: blocked.append({'url_sha256':sha256(destination.encode()),'reason':'destination lacks exact route/credential authority'})
            if queue: time.sleep(auth['spec']['limits']['interval_ms']/1000)
        return {'operations':observations,'blocked':blocked,'browser_execution':False,'security_verdict':'not_established'}
