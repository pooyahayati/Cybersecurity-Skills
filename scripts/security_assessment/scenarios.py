"""Actual HTTP and SQLite protected-state scenarios, never declared transition models."""

import copy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import secrets
import sqlite3
import time

from security_runtime.common import canonical, digest, fields, identifier, integer, read_file, regular, require
from security_runtime.traffic import TrafficController
from security_runtime.web_scope import fingerprint,url

FAMILIES={'account-recovery-mfa','session-revocation','owner-tenant-field-operation','file-handling',
          'webhook-signature-replay','idempotency-concurrency','secret-rotation','retention-deletion'}


def snapshot(spec):
    """Read real persisted tables through a separate read-only connection and transaction."""
    fields(spec,{'path','tables'})
    path=Path(spec['path']).absolute()
    require(path==path.resolve(strict=True),'oracle path must be canonical')
    regular(path)
    total=path.stat().st_size
    for suffix in ('-wal','-shm','-journal'):
        sidecar=Path(str(path)+suffix)
        if sidecar.exists() or sidecar.is_symlink():
            regular(sidecar);require(sidecar.resolve(strict=True)==sidecar,'oracle sidecar alias rejected')
            total+=sidecar.stat().st_size
    require(total<=64*1024**2,'oracle database and sidecars exceed limit')
    require(isinstance(spec['tables'],dict) and 0<len(spec['tables'])<=16,'invalid oracle tables')
    for table,columns in spec['tables'].items():
        require(re.fullmatch(r'[a-z][a-z0-9_]{0,63}',table) and isinstance(columns,list) and 0<len(columns)<=32
                and len(set(columns))==len(columns) and all(re.fullmatch(r'[a-z][a-z0-9_]{0,63}',c) for c in columns),'invalid oracle selection')
    connection=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=1)
    try:
        connection.enable_load_extension(False)
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,1024*1024)
        connection.setlimit(sqlite3.SQLITE_LIMIT_COLUMN,64)
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.execute('PRAGMA query_only=ON')
        connection.execute('BEGIN')
        deadline=time.monotonic()+2
        connection.set_progress_handler(lambda: int(time.monotonic()>deadline),1000)
        result={};output_bytes=0
        for table,columns in spec['tables'].items():
            schema=connection.execute("SELECT type FROM pragma_table_list WHERE schema='main' AND name=?",(table,)).fetchall()
            require(schema==[('table',)],'oracle requires ordinary persisted tables')
            rows=[]
            for row in connection.execute('SELECT '+','.join('"'+c+'"' for c in columns)+' FROM "'+table+'" LIMIT 1001'):
                value=dict(zip(columns,row));output_bytes+=len(canonical(value))
                require(len(rows)<1000 and output_bytes<=1024*1024,'oracle result exceeds limit')
                rows.append(value)
            result[table]=sorted(rows,key=canonical)
        require(len(canonical(result))<=1024*1024,'oracle snapshot exceeds limit')
        return result
    finally:
        connection.close()


class ScenarioController(TrafficController):
    binding_validator=None
    case_provider=None

    def binding(self,case,key,refresh=False):
        require(callable(self.binding_validator),'independent live deployment validator required')
        return self.binding_validator(case,key,refresh=refresh)

    def plan(self,case,spec):
        self.fresh_head()
        fields(spec,{'schema_version','id','family','authorization','source_sha256','deployment_evidence','oracle','identity_proofs','cases'})
        require(spec['schema_version']==1 and spec['family'] in FAMILIES,'unsupported scenario family')
        identifier(spec['id'])
        auth=self.guard(spec['authorization'],case)
        require(auth['spec']['profile']=='scenario','scenario traffic authority required')
        require(spec['source_sha256']==digest(case['source']['manifest']),'scenario source differs')
        # A separately retained independent launch/deployment observation is required;
        # the target cannot establish this link by returning its own version string.
        binding=self.binding(case,spec['deployment_evidence'],refresh=True)
        require(binding and binding['assessment']==case['scope']['id'] and binding['source_sha256']==spec['source_sha256']
                and binding['deployment']==auth['spec']['deployment'] and binding['url_binding_verified'] and binding['source_binding_verified'], 'independent source and URL deployment binding required')
        require(binding['database_host_path'] and Path(spec['oracle']['path']).resolve(strict=True)==Path(binding['database_host_path']).resolve(strict=True),'oracle does not read the actual service database')
        require(isinstance(spec['cases'],list) and 1<=len(spec['cases'])<=32,'invalid scenario cases')
        kinds=set(); seen=set()
        for row in spec['cases']:
            fields(row,{'id','kind','routes','statuses','response_sha256','expected_state','concurrent'})
            identifier(row['id']); require(row['id'] not in seen,'duplicate scenario case');seen.add(row['id'])
            require(row['kind'] in {'legitimate','prohibited','related-variant'},'invalid scenario case kind');kinds.add(row['kind'])
            require(type(row['concurrent']) is bool and isinstance(row['routes'],list) and 1<=len(row['routes'])<=4,'invalid scenario requests')
            require(len(set(row['routes']))==len(row['routes']) and all(r in {v['id'] for v in auth['spec']['routes']} for r in row['routes']),'scenario route unavailable')
            require(isinstance(row['statuses'],list) and len(row['statuses'])==len(row['routes']),'response predicates required')
            for statuses in row['statuses']:
                require(isinstance(statuses,list) and 0<len(statuses)<=5,'invalid response predicate')
                for status in statuses:integer(status,200,599)
            require(isinstance(row['response_sha256'],list) and len(row['response_sha256'])==len(row['routes']),'independent response content predicates required')
            for hashes in row['response_sha256']:
                require(isinstance(hashes,list) and 1<=len(hashes)<=5,'invalid response content predicate')
                for hashed in hashes:fingerprint(hashed)
            require(isinstance(row['expected_state'],dict),'independently specified state required')
        require(kinds=={'legitimate','prohibited','related-variant'},'legitimate, prohibited and related variant cases are all required')
        routes={r['id']:r for r in auth['spec']['routes']}
        used={routes[r]['credential'] for c in spec['cases'] for r in c['routes']} - {None}
        require(isinstance(spec['identity_proofs'],dict) and set(spec['identity_proofs'])==used,'valid identity proof is required for every credential')
        for label,proof in spec['identity_proofs'].items():
            fields(proof,{'route','body_sha256'});fingerprint(proof['body_sha256'])
            route=routes.get(proof['route'])
            require(route and route['method']=='GET' and route['credential']==label,'identity proof must use the same credential on an admitted read route')
        before=snapshot(spec['oracle'])
        require(all(set(c['expected_state'])==set(before) for c in spec['cases']),'state predicates must cover every selected table')
        with self.store.transaction() as tx:
            require(tx.get('scenario-plan',spec['id']) is None,'scenario plan ID cannot be reused')
            tx.put('scenario-plan',spec['id'],{'spec':copy.deepcopy(spec),'scope_sha256':case['scope_sha256'],'binding_sha256':digest(binding),'before':before,'consumed':False})
        return {'plan':spec['id'],'status':'planned','security_verdict':'not_established'}

    def exercise(self,case,key,bodies=None,credentials=None,ca=None):
        prepared=self.store.get('scenario-plan',key)
        require(prepared and digest(self.binding(case,prepared['spec']['deployment_evidence'],refresh=True))==prepared['binding_sha256'],'live deployment changed')
        require(snapshot(prepared['spec']['oracle'])==prepared['before'],'initial protected state changed after planning')
        with self.store.transaction() as tx:
            plan=tx.get('scenario-plan',key)
            require(plan and not plan['consumed'] and plan['scope_sha256']==case['scope_sha256'],'scenario unavailable or consumed')
            require(plan==prepared,'scenario plan changed during preflight')
            plan['consumed']=True;tx.put('scenario-plan',key,plan)
            operation='scenario-'+secrets.token_hex(16)
            tx.put('scenario-operation',operation,{'plan':key,'plan_sha256':digest(plan),'status':'unfinished','started_at':self.clock(),'cases':[],'identity_proofs':{}})
        results=[]
        try:
            proofs={}
            for label,proof in plan['spec']['identity_proofs'].items():
                result=self.execute(case,plan['spec']['authorization'],proof['route'],credentials=credentials,ca=ca)
                observed,_=self.observe(case,result['operation'])
                proofs[label]=result['operation']
                with self.store.transaction() as tx:
                    record=tx.get('scenario-operation',operation);record['identity_proofs']=proofs.copy();tx.put('scenario-operation',operation,record)
                require(observed['result']['status']==200 and observed['result']['body_sha256']==proof['body_sha256'],'credential identity is not independently established')
                time.sleep(self.guard(plan['spec']['authorization'],case)['spec']['limits']['interval_ms']/1000)
            require(snapshot(plan['spec']['oracle'])==plan['before'],'identity proofs changed protected state')
            for row in plan['spec']['cases']:
                require(digest(self.binding(case,plan['spec']['deployment_evidence']))==plan['binding_sha256'],'live deployment changed before request')
                def request(route):
                    return self.execute(case,plan['spec']['authorization'],route,body=(bodies or {}).get(route,b''),credentials=credentials,ca=ca)
                if row['concurrent']:
                    with ThreadPoolExecutor(max_workers=len(row['routes'])) as pool:
                        futures=[pool.submit(request,r) for r in row['routes']]
                        calls=[f.result() for f in futures]
                else:
                    calls=[]
                    for route in row['routes']:
                        calls.append(request(route))
                        time.sleep(self.guard(plan['spec']['authorization'],case)['spec']['limits']['interval_ms']/1000)
                observed=snapshot(plan['spec']['oracle'])
                require(digest(self.binding(case,plan['spec']['deployment_evidence']))==plan['binding_sha256'],'live deployment changed after request')
                response_pass=all(c['response_status'] in allowed and self.observe(case,c['operation'])[0]['result']['body_sha256'] in hashes
                    for c,allowed,hashes in zip(calls,row['statuses'],row['response_sha256']))
                state_pass=observed=={k:sorted(v,key=canonical) for k,v in row['expected_state'].items()}
                results.append({'case':row['id'],'kind':row['kind'],'operations':[c['operation'] for c in calls],
                    'response_pass':response_pass,'state_pass':state_pass,'state':observed})
                time.sleep(self.guard(plan['spec']['authorization'],case)['spec']['limits']['interval_ms']/1000)
            outcome='satisfied' if all(c['response_pass'] and c['state_pass'] for c in results) else 'failed'
            status='completed'
        except Exception:
            outcome,status='unverified','blocked'
        with self.store.transaction() as tx:
            record=tx.get('scenario-operation',operation)
            record.update(status=status,finished_at=self.clock(),cases=results,outcome=outcome)
            tx.put('scenario-operation',operation,record)
        return {'operation':operation,'status':status,'outcome':outcome,'qualified_profile':'HTTP plus selected SQLite persisted tables'}

    def compare(self,original,candidate):
        self.fresh_head()
        a=self.store.get('scenario-operation',original);b=self.store.get('scenario-operation',candidate)
        require(a and b and a['status']==b['status']=='completed','completed original and candidate required')
        pa=self.store.get('scenario-plan',a['plan']);pb=self.store.get('scenario-plan',b['plan'])
        require(callable(self.case_provider),'current assessment provider required')
        for record,plan in ((a,pa),(b,pb)):
            require(record['plan_sha256']==digest(plan),'retained scenario plan changed')
            auth=self.store.get('traffic-authority',plan['spec']['authorization'])
            case=self.case_provider(auth['assessment'])
            for label,operation in record['identity_proofs'].items():
                proof,_=self.observe(case,operation)
                require(proof['result']['status']==200 and proof['result']['body_sha256']==plan['spec']['identity_proofs'][label]['body_sha256'],'identity proof changed')
            for row in record['cases']:
                for operation in row['operations']:self.observe(case,operation)
            if record is b:
                require(digest(self.binding(case,plan['spec']['deployment_evidence']))==plan['binding_sha256'],'candidate deployment changed')
        require(pa['spec']['family']==pb['spec']['family'] and pa['spec']['cases']==pb['spec']['cases']
                and pa['spec']['source_sha256']!=pb['spec']['source_sha256'],'same independent cases and distinct actual source required')
        def semantics(plan):
            auth=self.store.get('traffic-authority',plan['spec']['authorization'])
            selected={r for c in plan['spec']['cases'] for r in c['routes']}|{p['route'] for p in plan['spec']['identity_proofs'].values()}
            return {'routes':sorted([{'id':r['id'],'path':url(r['url'])[3],'method':r['method'],'credential':r['credential'],
                'body_sha256':r['body_sha256'],'effect':r['effect']} for r in auth['spec']['routes'] if r['id'] in selected],key=lambda r:r['id']),
                'oracle_tables':plan['spec']['oracle']['tables'],'initial_state':plan['before'],'identity_proofs':plan['spec']['identity_proofs']}
        require(semantics(pa)==semantics(pb),'original and candidate request or oracle semantics differ')
        for original_case,candidate_case in zip(a['cases'],b['cases']):
            require(original_case['case']==candidate_case['case'] and len(original_case['operations'])==len(candidate_case['operations']),'case execution differs')
            for original_op,candidate_op in zip(original_case['operations'],candidate_case['operations']):
                require(self.store.get('traffic-operation',original_op)['credential_binding']==self.store.get('traffic-operation',candidate_op)['credential_binding'],'actual original and candidate credentials differ')
        state_failures=[r['case'] for r in a['cases'] if r['kind']!='legitimate' and not r['state_pass']]
        response_failures=[r['case'] for r in a['cases'] if r['kind']!='legitimate' and not r['response_pass']]
        failed=state_failures+response_failures
        require(failed and b['outcome']=='satisfied','original protected-state failure and complete candidate success required')
        return {'outcome':'satisfied','original':original,'candidate':candidate,'reproduced_protected_state_failures':state_failures,'reproduced_response_contract_failures':response_failures,
                'claim':'Only the selected stack, cases, independent state and source/deployment bindings qualify.'}
