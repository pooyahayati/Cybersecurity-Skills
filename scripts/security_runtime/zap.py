"""Current official stable ZAP image and independently resolved selected add-ons."""

import base64
import copy
import hashlib
from pathlib import Path
import re
import secrets
import xml.etree.ElementTree as ET

from .common import canonical,digest,fields,parse,read_file,require,sha256
from .controller import REVIEW_AREAS,write_bundle,HEAD_RESOURCES,selected_tree
from .sources import GitHub
from .traffic import TrafficController

CHANNEL='docker.io/zaproxy/zap-stable:latest'
ADDONS={'automation','exim','network','commonlib','pscanrules','pscan','reports','callhome'}


def catalog(raw):
    require(len(raw)<=1024*1024 and b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(),'unsupported marketplace XML')
    root=ET.fromstring(raw)
    result={}
    for identity in sorted(ADDONS):
        rows=root.findall('addon_'+identity)
        require(len(rows)==1,'selected add-on absent or ambiguous')
        row=rows[0]
        filename=row.findtext('file');hashed=row.findtext('hash');version=row.findtext('version')
        status=row.findtext('status')
        require(isinstance(filename,str) and re.fullmatch(re.escape(identity)+r'-(release|beta|alpha)-[0-9A-Za-z.]+\.zap',filename)
            and re.fullmatch(r'SHA-256:[0-9a-f]{64}',str(hashed)) and re.fullmatch(r'[0-9]+(?:\.[0-9]+){0,3}',str(version))
            and filename==identity+'-'+str(status)+'-'+version+'.zap','invalid add-on identity')
        dependencies=[a.findtext('id') for a in row.findall('dependencies/addons/addon')]
        require(set(dependencies)<=ADDONS,'unreviewed add-on dependency')
        result[identity]={'file':filename,'sha256':hashed[8:],'version':version,'status':row.findtext('status'),'dependencies':dependencies}
    return result


def official_file(github,revision,name):
    """Fresh official API bytes at the resolved commit; no raw-host/cache fallback."""
    require(re.fullmatch(r'[0-9a-f]{40}',revision) and re.fullmatch(r'ZapVersions(?:-[0-9]+\.[0-9]+)?\.xml',name),'invalid official catalog identity')
    value=github.json('zaproxy/zap-admin/contents/'+name+'?ref='+revision)
    require(value.get('type')=='file' and value.get('path')==name and value.get('encoding')=='base64'
        and type(value.get('size')) is int and 0<value['size']<=1024*1024 and re.fullmatch(r'[0-9a-f]{40}',str(value.get('sha')))
        and isinstance(value.get('content'),str),'official catalog content unavailable')
    raw=base64.b64decode(value['content'].replace('\n',''),validate=True)
    require(len(raw)==value['size'] and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==value['sha'],'official Git blob integrity differs')
    return raw


class ZapAnalysis(TrafficController):
    def __init__(self,store,package,upstream=None,clock=None,docker=None,source_client=None):
        import time
        super().__init__(store,package,upstream,clock or time.time)
        self.docker=docker
        self.source_client=source_client or GitHub()

    def resolve(self):
        require(self.docker is not None,'local Docker required')
        self.docker.observe()
        self.docker.checked(['pull',CHANNEL],timeout=300)
        rows=parse(self.docker.checked(['image','inspect',CHANNEL]))
        require(len(rows)==1 and rows[0].get('Os')=='linux' and not rows[0].get('Config',{}).get('Volumes'),'unsupported ZAP image')
        image=rows[0]
        refs=[r for r in image.get('RepoDigests',[]) if re.fullmatch(r'(?:docker.io/)?zaproxy/zap-stable@sha256:[0-9a-f]{64}',r)]
        require(len(refs)==1,'immutable ZAP image unavailable')
        github=self.source_client
        spec={'id':'zap-marketplace','kind':'tool','repository':'zaproxy/zap-admin','repository_id':30185465,'owner_id':6716868,
              'include':['ZapVersions.xml'],'asset':None,'max_download_bytes':1024*1024,'max_unpacked_bytes':1024*1024,'data_max_age_seconds':None}
        revision=github.resolve(spec)
        core_raw=official_file(github,revision['identity']['revision'],'ZapVersions.xml')
        require(b'<!DOCTYPE' not in core_raw.upper() and b'<!ENTITY' not in core_raw.upper(),'unsupported core metadata')
        core=ET.fromstring(core_raw).findtext('core/version')
        require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',str(core)),'stable ZAP core unavailable')
        name='ZapVersions-'+'.'.join(core.split('.')[:2])+'.xml'
        raw=official_file(github,revision['identity']['revision'],name)
        return {'image':{'reference':refs[0],'image_id':image['Id'],'architecture':image['Architecture']},'channel':CHANNEL,
                'core':core,'marketplace_revision':revision['identity'],'marketplace_sha256':sha256(raw),'addons':catalog(raw)}

    def prepare(self):
        head=self.fresh_head(); resources=self.resolve()
        candidate='zap-'+digest(resources)
        with self.store.transaction() as tx:
            tx.put('zap-candidate',candidate,{'resources':resources,'head':head,'prepared_at':self.clock()})
        return {'candidate':candidate,'resources':resources,'status':'review_required'}

    def review(self,decision):
        fields(decision,{'candidate','reviewer','decision','checks'})
        require(isinstance(decision['reviewer'],str) and decision['reviewer'].strip(),'reviewer required')
        require(decision['decision'] in {'accept','reject'},'invalid review decision')
        fields(decision['checks'],REVIEW_AREAS)
        for row in decision['checks'].values():
            fields(row,{'result','evidence'})
            require(row['result'] in {'pass','fail'} and isinstance(row['evidence'],str) and row['evidence'].strip(),'review evidence required')
        require(decision['decision']!='accept' or all(r['result']=='pass' for r in decision['checks'].values()),'failed review cannot accept')
        with self.store.transaction() as tx:
            candidate=tx.get('zap-candidate',decision['candidate']);require(candidate,'candidate absent')
            tx.put('zap-review',decision['candidate'],{'candidate_sha256':digest(candidate),'decision':copy.deepcopy(decision)})
        return {'status':decision['decision']}

    def analyze(self,case,candidate_id,operations):
        require(isinstance(operations,list) and 1<=len(operations)<=32 and len(set(operations))==len(operations),'invalid capture selection')
        head=self.fresh_head()
        candidate=self.store.get('zap-candidate',candidate_id);review=self.store.get('zap-review',candidate_id)
        require(candidate and review and review['candidate_sha256']==digest(candidate) and review['decision']['decision']=='accept','reviewed exact ZAP resources required')
        require(candidate['resources']==self.resolve(),'ZAP image, core or selected add-ons changed; review current resources')
        entries=[]; captures={}
        for operation in operations:
            record,auth=self.observe(case,operation)
            require(auth['spec']['profile']=='capture','only admitted capture traffic is supported')
            route=next(r for r in auth['spec']['routes'] if r['id']==record['route']);response=record['result']
            captures[operation]=digest(record)
            entries.append({'startedDateTime':'2000-01-01T00:00:00Z','time':0,
                'request':{'method':route['method'],'url':route['url'],'httpVersion':'HTTP/1.1','cookies':[],'headers':[],
                           'queryString':[],'headersSize':-1,'bodySize':0},
                'response':{'status':response['status'],'statusText':'Captured','httpVersion':'HTTP/1.1','cookies':[],
                    'headers':[{'name':k,'value':v} for k,v in response['headers']],
                    'content':{'size':response['body_bytes'],'mimeType':next((v for k,v in response['headers'] if k.lower()=='content-type'),'application/octet-stream'),
                               'text':response['body'],'encoding':'base64'},'redirectURL':'','headersSize':-1,'bodySize':response['body_bytes']},
                'cache':{},'timings':{'send':0,'wait':0,'receive':0}})
        har=canonical({'log':{'version':'1.2','creator':{'name':'Cybersecurity-Skills','version':'1'},'entries':entries}})
        require(len(har)<=12*1024**2,'capture exceeds limit')
        stage,manifest=write_bundle(self.store.root/'quarantine',{'traffic.har':har,'zap-policy.json':canonical(candidate['resources'])})
        operation='op-'+secrets.token_hex(16)
        def guard():
            require(selected_tree(self.package,HEAD_RESOURCES)==head['manifest'],'analysis implementation changed')
            require(self.store.get('zap-candidate',candidate_id)==candidate,'analysis candidate changed')
            for key,expected in captures.items():require(digest(self.observe(case,key)[0])==expected,'capture producer changed')
            require(self.store.get('zap-review',candidate_id)==review,'analysis review changed')
        with self.store.transaction() as tx:
            tx.put('zap-operation',operation,{'assessment':case['scope']['id'],'scope_sha256':case['scope_sha256'],'candidate':candidate_id,
                'candidate_sha256':digest(candidate),'captures':captures,'inputs':manifest,'status':'unfinished','started_at':self.clock()})
        try:
            with (self.store.root/(operation+'.zap-output')).open('xb') as output:
                result=self.docker.execute(operation,candidate['resources']['image'],self.package,stage,
                    {'entrypoint':'scripts/c3_zap_worker.py','interpreter':'native','arguments':[],'timeout_seconds':180,'max_output_bytes':2*1024**2},
                    {'memory_mb':1536,'cpus':2,'pids':128,'tmpfs_mb':256},guard,output)
            require(result['exit_code']==0,'offline ZAP analysis failed')
            raw=read_file(self.store.root,operation+'.zap-output',2*1024**2)
            require(sha256(raw)==result['sha256'] and len(raw)==result['bytes'],'analysis output bytes differ')
            value=parse(raw,2*1024**2)
            require(value.get('adapter')=='c3-zap-passive' and value.get('policy_sha256')==digest(candidate['resources']),'analysis producer differs')
            with self.store.transaction() as tx:
                record=tx.get('zap-operation',operation);record.update(status='completed',result=result,finished_at=self.clock(),report=value)
                tx.put('zap-operation',operation,record)
        except Exception:
            with self.store.transaction() as tx:
                record=tx.get('zap-operation',operation);record.update(status='blocked',finished_at=self.clock());tx.put('zap-operation',operation,record)
            raise
        return {'operation':operation,'status':'completed','leads':len(value['leads']),'security_verdict':'not_established'}
