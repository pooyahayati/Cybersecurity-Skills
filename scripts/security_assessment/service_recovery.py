"""Measured SQLite service recovery and independently authenticated log/alert hops."""

import hmac
from pathlib import Path
import secrets
import sqlite3

from security_runtime.common import canonical,digest,fields,identifier,integer,parse,read_file,regular,require,sha256,text
from .scenarios import snapshot


def verify_hops(expected,logs,keys):
    fields(expected,{'exercise','event','event_sha256','hops','started_at','deadline','owner'})
    identifier(expected['exercise']);identifier(expected['event'])
    require(isinstance(expected['hops'],list) and 3<=len(expected['hops'])<=8 and len(set(expected['hops']))==len(expected['hops']),'target, collector and receiver hops required')
    require(set(logs)==set(keys)==set(expected['hops']),'every independently controlled hop is required')
    require(len(set(keys.values()))==len(keys),'hop keys must be independent')
    previous=expected['event_sha256'];observed=[]
    for hop in expected['hops']:
        raw=logs[hop];require(isinstance(raw,bytes) and len(raw)<=1024*1024,'hop log exceeds limit')
        require(isinstance(keys[hop],bytes) and len(keys[hop])>=32,'independent hop key required')
        rows=[parse(line,16384) for line in raw.splitlines() if line]
        matches=[r for r in rows if r.get('exercise')==expected['exercise'] and r.get('event')==expected['event']]
        require(len(matches)==1,'missing or duplicate actual alert hop')
        row=matches[0]
        fields(row,{'exercise','event','hop','previous_sha256','observed_at','owner','mac'})
        payload={k:v for k,v in row.items() if k!='mac'}
        require(row['hop']==hop and row['previous_sha256']==previous and row['owner']==expected['owner']
                and expected['started_at']<=row['observed_at']<=expected['deadline'],'alert event correlation failed')
        require(isinstance(row['mac'],str) and hmac.compare_digest(row['mac'],hmac.new(keys[hop],canonical(payload),'sha256').hexdigest()),'forged alert acknowledgment')
        previous=digest(row);observed.append({'hop':hop,'record_sha256':previous,'observed_at':row['observed_at']})
    require(all(a['observed_at']<=b['observed_at'] for a,b in zip(observed,observed[1:])),'alert hops are out of order')
    return {'outcome':'satisfied','hops':observed,'latency_seconds':observed[-1]['observed_at']-expected['started_at'],
        'claim':'Authenticated event through the selected instrumented target/log/receiver transports; other receivers, retention and escalation actions are unverified.'}


class ServiceRecovery:
    backup_probe=None
    def __init__(self,store,traffic,clock):self.store,self.traffic,self.clock=store,traffic,clock

    def plan_detection(self,case,spec):
        self.traffic.fresh_head()
        fields(spec,{'id','event','hops','owner','timeout_seconds','application_binding','target_path'})
        identifier(spec['id']);identifier(spec['event']);text(spec['owner'],256);integer(spec['timeout_seconds'],1,300)
        require(spec['hops']==['target','collector','receiver'],'qualified instrumented three-hop profile required')
        for hop in spec['hops']:identifier(hop)
        require(spec['target_path']=='/audit-exercise','qualified target instrumentation endpoint required')
        binding=self.traffic.binding(case,spec['application_binding'],refresh=True)
        require(binding['source_binding_verified'] and binding['url_binding_verified'],'independent live target instrumentation binding required')
        now=self.clock();nonce=secrets.token_hex(32)
        event={'exercise':spec['id'],'event':spec['event'],'nonce':nonce,'classification':'synthetic-security-exercise'}
        expected={'exercise':spec['id'],'event':spec['event'],'event_sha256':digest(event),'hops':spec['hops'],'started_at':now,
                  'deadline':now+spec['timeout_seconds'],'owner':spec['owner']}
        keys={hop:secrets.token_bytes(32).hex() for hop in spec['hops']}
        with self.store.transaction() as tx:
            require(tx.get('detection-exercise',spec['id']) is None,'exercise ID cannot be reused')
            tx.put('detection-exercise',spec['id'],{'assessment':case['scope']['id'],'scope_sha256':case['scope_sha256'],
                'expected':expected,'event':event,'keys':keys,'status':'planned','application_binding':spec['application_binding'],
                'binding_sha256':digest(binding),'target_path':spec['target_path'],'deployment':binding['deployment']})
        # Provision each key only to its corresponding independently controlled hop.
        # This private path is never a public report or automatic notification.
        path=self.store.root/('detection-provision-'+spec['id']+'.json')
        with path.open('xb') as output:output.write(canonical({'expected':expected,'event':event,'target_key':keys['target']}))
        return {'exercise':spec['id'],'status':'planned','private_provisioning_path':str(path),'security_verdict':'not_established'}

    def detection(self,case,key,paths,trigger_operation):
        self.traffic.fresh_head()
        record=self.store.get('detection-exercise',key)
        require(record and record['status']=='listening' and record['scope_sha256']==case['scope_sha256'],'actual instrumented listeners required')
        require(digest(self.traffic.binding(case,record['application_binding'],refresh=True))==record['binding_sha256'],'instrumented target changed')
        trigger,auth=self.traffic.observe(case,trigger_operation)
        route=next(r for r in auth['spec']['routes'] if r['id']==trigger['route'])
        from urllib.parse import urlsplit
        require(auth['spec']['profile']=='scenario' and auth['spec']['deployment']==record['deployment']
                and urlsplit(route['url']).path==record['target_path'] and route['method']=='POST' and route['effect']=='synthetic-write'
                and route['body_sha256']==digest(record['event']) and 200<=trigger['result']['status']<300
                and record['expected']['started_at']<=trigger['started_at']<=record['expected']['deadline'], 'exact admitted synthetic target event trigger required')
        require(set(paths)==set(record['expected']['hops']),'all selected hop logs required')
        logs={}
        for hop,value in paths.items():
            path=Path(value).absolute()
            require(path==path.resolve(strict=True) and not path.is_relative_to(self.traffic.package),'private actual transport log required')
            logs[hop]=read_file(path.parent,path.name,1024*1024)
        try:
            result=verify_hops(record['expected'],logs,{h:bytes.fromhex(k) for h,k in record['keys'].items()})
            import base64
            response=parse(base64.b64decode(trigger['result']['body'],validate=True),16384)
            fields(response,{'audit_event'})
            require(logs['target']==canonical(response['audit_event'])+b'\n','target audit row does not match the actual bound target response')
            for hop in ('collector','receiver'):
                observed=self.store.get('detection-hop',key+'-'+hop)
                require(observed and observed['listener']==record['listener'] and observed['transport']=='actual-owned-loopback-http'
                    and trigger['started_at']<=observed['received_at']<=record['expected']['deadline']
                    and logs[hop]==canonical(observed['row'])+b'\n','actual instrumented transport receipt differs')
        except Exception:
            result={'outcome':'failed','reason':'Actual selected log/receiver chain is incomplete, inconsistent or unauthenticated.'}
        record.update(status='completed',result=result,logs={h:sha256(raw) for h,raw in logs.items()},trigger=trigger_operation,
                      trigger_sha256=digest(trigger),finished_at=self.clock())
        with self.store.transaction() as tx:tx.put('detection-exercise',key,record)
        return {'exercise':key,'status':'completed',**result}

    def listen(self,case,key):
        from security_runtime.detection import DetectionListeners
        self.traffic.fresh_head()
        record=self.store.get('detection-exercise',key)
        require(record and record['scope_sha256']==case['scope_sha256'],'exercise scope differs')
        head=self.traffic.fresh_head()
        def guard():
            from security_runtime.controller import selected_tree,HEAD_RESOURCES
            require(selected_tree(self.traffic.package,HEAD_RESOURCES)==head['manifest'],'listener implementation changed')
            require(not self.store.get('revocation','head',False),'listener producer revoked')
        listeners=DetectionListeners(self.store,key,guard,self.clock)
        try:listeners.start();return listeners.wait()
        finally:listeners.close()

    def capture(self,case,spec):
        self.traffic.fresh_head()
        fields(spec,{'id','oracle','watermark_table','watermark_column','max_loss_events','max_recovery_seconds','service_expectation','application_binding'})
        fields(spec['service_expectation'],{'body_sha256','denial_body_sha256','allowed_credential','compromised_credential','compromised_prior_operation','deployment'})
        from security_runtime.web_scope import fingerprint
        fingerprint(spec['service_expectation']['body_sha256'])
        fingerprint(spec['service_expectation']['denial_body_sha256'])
        for name in ('allowed_credential','compromised_credential','deployment'):identifier(spec['service_expectation'][name])
        require(spec['service_expectation']['allowed_credential']!=spec['service_expectation']['compromised_credential'],'distinct credentials required')
        binding=self.traffic.binding(case,spec['application_binding'],refresh=True)
        require(binding['source_binding_verified'] and binding['url_binding_verified'] and binding['database_host_path']
                and Path(binding['database_host_path']).resolve(strict=True)==Path(spec['oracle']['path']).resolve(strict=True),'backup source is not the actual selected application database')
        prior,prior_auth=self.traffic.observe(case,spec['service_expectation']['compromised_prior_operation'])
        prior_route=next(r for r in prior_auth['spec']['routes'] if r['id']==prior['route'])
        require(prior_auth['spec']['deployment']==binding['deployment'] and prior_route['method']=='GET'
                and prior_route['credential']==spec['service_expectation']['compromised_credential'] and prior['result']['status']==200
                and self.clock()-300<=prior['finished_at']<=self.clock(),'prior successful compromised-credential access required')
        identifier(spec['id']);integer(spec['max_loss_events'],0,1000);integer(spec['max_recovery_seconds'],1,3600)
        before=snapshot(spec['oracle'])
        table,column=spec['watermark_table'],spec['watermark_column']
        require(table in before and column in spec['oracle']['tables'][table],'independent committed-event watermark required')
        marks=[r[column] for r in before[table]]
        require(marks and all(type(v) is int and v>=0 for v in marks) and len(set(marks))==len(marks),'invalid committed-event watermark')
        path=self.store.root/('service-backup-'+secrets.token_hex(16)+'.sqlite3')
        source=Path(spec['oracle']['path']).resolve(strict=True)
        started=self.clock()
        original=sqlite3.connect(source.as_uri()+'?mode=ro',uri=True,timeout=1)
        target=sqlite3.connect(path)
        try:
            original.enable_load_extension(False);original.execute('PRAGMA trusted_schema=OFF')
            page_size=original.execute('PRAGMA page_size').fetchone()[0]
            def progress(status,remaining,total):
                require(self.clock()-started<=10 and total*page_size<=64*1024**2,'backup capture time/size bound')
            original.backup(target,pages=128,progress=progress,sleep=0.01)
            target.set_progress_handler(lambda:int(self.clock()-started>10),1000)
            require(target.execute('PRAGMA quick_check').fetchall()==[('ok',)],'backup consistency failed')
        finally:original.close();target.close()
        raw=read_file(self.store.root,path.name,64*1024**2)
        backup_oracle={**spec['oracle'],'path':str(path)}
        require(snapshot(backup_oracle)==before,'database changed during independent capture')
        require(self.traffic.binding(case,spec['application_binding'])==binding,'application changed during capture')
        record={'assessment':case['scope']['id'],'scope_sha256':case['scope_sha256'],'spec':spec,'backup':path.name,'backup_sha256':sha256(raw),
                'snapshot':before,'capture_started_at':started,'captured_at':self.clock(),'watermark':max(marks),'status':'captured',
                'application_binding_sha256':digest(binding),'compromised_prior_sha256':digest(prior),
                'compromised_credential_binding':prior['credential_binding'],'prior_resource_path':__import__('urllib.parse',fromlist=['urlsplit']).urlsplit(prior_route['url']).path}
        with self.store.transaction() as tx:
            require(tx.get('service-recovery',spec['id']) is None,'recovery identity cannot be reused')
            tx.put('service-recovery',spec['id'],record)
        return {'id':spec['id'],'status':'captured','security_verdict':'not_established'}

    def restore(self,case,key):
        self.traffic.fresh_head()
        record=self.store.get('service-recovery',key)
        require(record and record['status']=='captured' and record['scope_sha256']==case['scope_sha256'],'recovery unavailable')
        require(digest(self.traffic.binding(case,record['spec']['application_binding'],refresh=True))==record['application_binding_sha256'],'backup application identity changed before loss measurement')
        current=snapshot(record['spec']['oracle'])
        table,column=record['spec']['watermark_table'],record['spec']['watermark_column']
        original_ids={r[column] for r in current[table]};backup_ids={r[column] for r in record['snapshot'][table]}
        require(backup_ids<=original_ids,'committed-event history differs; loss cannot be measured')
        raw=read_file(self.store.root,record['backup'],64*1024**2)
        require(sha256(raw)==record['backup_sha256'],'backup bytes changed')
        started=self.clock()
        destination=self.store.root/('service-restore-'+secrets.token_hex(16)+'.sqlite3')
        with destination.open('xb') as output:output.write(raw)
        restored_oracle={**record['spec']['oracle'],'path':str(destination)}
        require(snapshot(restored_oracle)==record['snapshot'],'restored data differs')
        record.update(status='restored-awaiting-service',restore_started_at=started,restored=destination.name,
                      committed_before_restore=sorted(original_ids),lost_committed_events=sorted(original_ids-backup_ids))
        with self.store.transaction() as tx:tx.put('service-recovery',key,record)
        return {'id':key,'status':record['status'],'restored_path':str(destination),'security_verdict':'not_established'}

    def finish(self,case,key,positive,compromised,backup_access,service_binding):
        self.traffic.fresh_head()
        record=self.store.get('service-recovery',key)
        require(record and record['status']=='restored-awaiting-service' and record['scope_sha256']==case['scope_sha256'],'recovery service check unavailable')
        prior,_=self.traffic.observe(case,record['spec']['service_expectation']['compromised_prior_operation'])
        require(digest(prior)==record['compromised_prior_sha256'],'prior valid credential evidence changed')
        allowed,allow_auth=self.traffic.observe(case,positive);denied,deny_auth=self.traffic.observe(case,compromised)
        require(positive!=compromised and allowed['credential_binding']!=denied['credential_binding'],'distinct legitimate and compromised credentials required')
        allow_route=next(r for r in allow_auth['spec']['routes'] if r['id']==allowed['route'])
        deny_route=next(r for r in deny_auth['spec']['routes'] if r['id']==denied['route'])
        expected=record['spec']['service_expectation']
        binding=self.traffic.binding(case,service_binding,refresh=True)
        require(binding and binding['url_binding_verified'] and binding['assessment']==case['scope']['id']
                and binding['deployment']==allow_auth['spec']['deployment']==deny_auth['spec']['deployment']==expected['deployment']
                and Path(binding['database_host_path']).resolve(strict=True)==(self.store.root/record['restored']).resolve(strict=True), 'usable service is not independently bound to restored database')
        require(allow_route['credential']==expected['allowed_credential'] and deny_route['credential']==expected['compromised_credential'],'service credentials differ from prior plan')
        require(denied['credential_binding']==record['compromised_credential_binding'],'denied credential was never proven valid before recovery')
        from urllib.parse import urlsplit
        require(urlsplit(deny_route['url']).path==record['prior_resource_path'],'prior and restored protected resources differ')
        require(allow_route['url']==deny_route['url'] and allow_route['method']==deny_route['method']=='GET','same restored resource must be exercised')
        require(allowed['started_at']>=record['restore_started_at'] and denied['started_at']>=record['restore_started_at'],'service observations predate restore')
        proof=self.store.get('backup-access-operation',backup_access)
        require(proof and proof['assessment']==case['scope']['id'] and proof['backup_sha256']==record['backup_sha256']
                and proof['binding']==service_binding and proof['binding_sha256']==digest(binding) and proof['container']==binding['container'], 'actual backup isolation attempt for the restored application required')
        require(callable(self.backup_probe),'fresh backup isolation probe required')
        fresh=self.backup_probe(case['scope']['id'],key,service_binding)
        proof=self.store.get('backup-access-operation',fresh['operation'])
        current=snapshot({**record['spec']['oracle'],'path':str(self.store.root/record['restored'])})
        elapsed=self.clock()-record['restore_started_at']
        checks={'usable_service':allowed['result']['status']==200 and allowed['result']['body_sha256']==expected['body_sha256'],
                'compromised_access_revoked':denied['result']['status'] in {401,403} and denied['result']['body_sha256']==expected['denial_body_sha256'] and denied['result']['body_sha256']!=allowed['result']['body_sha256'],
                'restored_state':current==record['snapshot'],'backup_isolated':proof['read_succeeded'] is False,
                'loss_within_budget':len(record['lost_committed_events'])<=record['spec']['max_loss_events'],
                'recovery_within_budget':0<=elapsed<=record['spec']['max_recovery_seconds']}
        record.update(status='completed',outcome='satisfied' if all(checks.values()) else 'failed',checks=checks,
                      measured_service_recovery_seconds=elapsed,finished_at=self.clock(),positive=positive,compromised=compromised,backup_access=fresh['operation'],prior_backup_access=backup_access)
        with self.store.transaction() as tx:tx.put('service-recovery',key,record)
        return {'id':key,'status':'completed','outcome':record['outcome'],'checks':checks,'measured_service_recovery_seconds':elapsed,
            'measured_lost_committed_events':len(record['lost_committed_events']),
            'limits':['Measured from explicit restore start through observed selected authenticated GET/read usability, not production outage onset. Other read/write business workflows require separate scenarios. RPO measured in committed selected events, not an inferred wall-clock data-loss window.']}
