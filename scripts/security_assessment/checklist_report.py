"""Actionable, private, bounded observation reports; no automatic checklist closure."""

from security_runtime.common import canonical,digest,read_file,require,sha256

GUIDANCE={
    'account-recovery-mfa':'Bind a single-use, expiring recovery proof and a verified second factor to the intended account; repeat recovery and wrong-account tests.',
    'session-revocation':'Revoke server-side sessions and refresh credentials consistently; retest read and write access using the same formerly valid credential.',
    'owner-tenant-field-operation':'Authorize the acting identity, tenant, resource, operation and writable fields before reading or changing data; preserve owner behavior.',
    'file-handling':'Constrain file names, sizes and types; isolate storage and prevent execution; retest traversal, active content and legitimate uploads.',
    'webhook-signature-replay':'Verify the exact signed payload, timestamp and unique event before committing effects; reject duplicate and stale events atomically.',
    'idempotency-concurrency':'Bind the idempotency key to identity and request meaning; enforce uniqueness and atomic effects in the database under concurrent requests.',
    'secret-rotation':'Activate the replacement credential and revoke every old access path; verify both old denial and legitimate replacement use.',
    'retention-deletion':'Authorize deletion and apply the retention policy to primary records and every selected copy; verify independent persisted state.',
}


def build_report(control,case):
    key=case['scope']['id'];store=control.store
    kinds=('checklist-execution','zap-operation','scenario-operation','scenario-plan','deployment-binding',
           'pipeline-operation','detection-exercise','service-recovery','traffic-operation','traffic-authority')
    with store.transaction() as tx:records={kind:tx.list(kind) for kind in kinds}
    rows=[]
    for identity,record in records['checklist-execution'].items():
        if record['assessment']!=key:continue
        producer=store.get('operation',identity)
        require(producer and digest(producer)==record['operation_sha256'],'offline producer changed')
        raw=read_file(store.root,identity+'.output',8*1024**2)
        require(sha256(raw)==record['output_sha256'],'offline output changed')
        rows.append({'id':identity,'stage':record['stage'],'observed_outcome':record['report']['outcome'],
            'observed_at':record['recorded_at'],'producer_operation':record['operation'],'scope_sha256':record['scope_sha256'],
            'evidence':record['report'],'next_action':'Review exact affected components and supported inventory. Apply a compatible fix, rebuild and repeat with current independent data.' if record['stage']=='c2' else
            'Match the approved publisher key, artifact, builder, workflow and source revision. Rebuild and verify again; signature validity is not deployment identity.'})
    for identity,record in records['zap-operation'].items():
        if record['assessment']!=key:continue
        for operation,expected in record['captures'].items():
            require(digest(store.get('traffic-operation',operation))==expected,'captured producer changed')
        rows.append({'id':identity,'stage':'c3','observed_outcome':record['status'],
            'observed_at':record.get('finished_at',record['started_at']),'captures':list(record['captures']),'scope_sha256':record['scope_sha256'],
            'evidence':record.get('report',{}),'next_action':'Treat each passive alert as an unconfirmed lead. Inspect the affected captured route, establish impact and counterevidence, then retest the real response.'})
    for identity,record in records['scenario-operation'].items():
        plan=records['scenario-plan'].get(record['plan'])
        if not plan:continue
        authority=store.get('traffic-authority',plan['spec']['authorization'])
        if authority['assessment']!=key:continue
        require(record['plan_sha256']==digest(plan),'scenario producer changed')
        failures=[{'case':row['case'],'kind':row['kind'],'response_pass':row['response_pass'],'state_pass':row['state_pass'],
            'operations':row['operations']} for row in record['cases']]
        rows.append({'id':identity,'stage':'c4','family':plan['spec']['family'],'observed_outcome':record.get('outcome','unverified'),
            'execution_status':record['status'],'observed_at':record.get('finished_at',record['started_at']),
            'deployment_binding':plan['spec']['deployment_evidence'],'source_sha256':plan['spec']['source_sha256'],
            'cases':failures,'next_action':GUIDANCE[plan['spec']['family']] if record['status']=='completed' else
            'Execution is incomplete. Inspect actual target state before any retry; consumed requests are not refunded. Preserve the original record and use new explicit authority.'})
    attempts=[]
    for identity,record in records['traffic-operation'].items():
        auth=records['traffic-authority'].get(record['authorization'])
        require(auth is not None,'traffic authority missing')
        if auth['assessment']!=key:continue
        attempts.append({'operation':identity,'deployment':auth['spec']['deployment'],'route':record['route'],
            'status':record['status'],'observed_at':record.get('finished_at',record['started_at']),
            'action':'Inspect actual state before retrying an uncertain write.' if record['status']!='completed' else 'Observation only; no automatic security verdict.'})
    for kind,stage in (('deployment-binding','c5'),('pipeline-operation','c5'),('detection-exercise','c6'),('service-recovery','c6')):
        for identity,record in records[kind].items():
            if record['assessment']!=key:continue
            result=record.get('result',record)
            rows.append({'id':identity,'stage':stage,'observed_outcome':result.get('outcome',record.get('status','unverified')),
                'observed_at':record.get('finished_at',record.get('observed_at',record.get('captured_at'))),
                'deployment':record.get('deployment'),'container':record.get('container'),'repository':result.get('repository'),
                'measured_service_recovery_seconds':record.get('measured_service_recovery_seconds'),
                'measured_lost_committed_events':len(record['lost_committed_events']) if 'lost_committed_events' in record else None,
                'checks':result.get('checks',{}),'limits':result.get('limits',[]),
                'next_action':'Resolve failed effective settings and preserve legitimate service access; verify the actual environment after correction.' if stage=='c5' else
                'Repair missing transport hops, isolate backups and restore a usable service. Verify committed data loss and reject the formerly valid compromised credential.'})
    value={'schema_version':1,'assessment':key,'scope_sha256':case['scope_sha256'],'generated_at':control.clock(),
        'observation_count':len(rows),'observations':rows,'traffic_attempts':attempts,'security_verdict':'not_established',
        'checklist_item_outcomes':'all_unverified_until_complete_item_evidence',
        'freshness':'Historical observations only. This report does not renew expired authority, currentness, producer review or a target verdict.',
        'gaps':['Unsupported stacks, cloud accounts, browsers, unselected routes/tables and untested checklist requirements remain unverified.',
                'Use the separate 36-item checklist plan and M2 evidence/counterevidence review; these observations do not automatically close a broad control or child item.']}
    path=store.root/('checklist-report-'+key+'.json')
    # Atomic replacement of this generated report only; retained observations survive.
    temporary=store.root/('checklist-report-'+key+'.pending')
    require(not temporary.exists(),'unfinished report requires inspection')
    with temporary.open('xb') as output:output.write(canonical(value)+b'\n')
    temporary.replace(path)
    return {'status':'reported','private_report':str(path),'observations':len(rows),'security_verdict':'not_established'}
