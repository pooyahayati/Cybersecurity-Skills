"""Typed C2-C6 evidence, separate from planning and broad legacy control verdicts."""

from pathlib import Path
import secrets

from security_runtime.advisory import validate_metadata
from security_runtime.common import digest,fields,identifier,parse,read_file,require,sha256
from security_runtime.controller import selected_tree
from .scenarios import ScenarioController
from security_runtime.zap import ZapAnalysis
from .effective import inspect_container,pipeline
from .resilience import ResilienceReview
from .service_recovery import ServiceRecovery


class ChecklistReview(ResilienceReview):
    def __init__(self,store,package,clock=None,upstream=None,docker=None):
        import time
        super().__init__(store,package,clock=clock or time.time,upstream=upstream,docker=docker)
        self.traffic=ScenarioController(store,package,upstream,self.clock)
        self.traffic.binding_validator=self.validate_binding
        self.traffic.case_provider=self.case
        self.zap=ZapAnalysis(store,package,upstream,self.clock,docker)
        self.service_recovery=ServiceRecovery(store,self.traffic,self.clock)
        self.service_recovery.backup_probe=self.backup_access

    def case(self,key):
        with self.store.transaction() as tx:return self._case(tx,key)

    def validate_binding(self,case,key,refresh=False):
        require(self.docker is not None,'local Docker required')
        record=self.store.get('deployment-binding',key)
        require(record and record['scope_sha256']==case['scope_sha256'],'deployment binding unavailable')
        controller=self.traffic.controller;controller.docker=self.docker
        runtime=controller.check_current(record['runtime_candidate']) if refresh else controller.candidate(record['runtime_candidate'])
        controller.reviewed(record['runtime_candidate'],runtime,self.store)
        observed=inspect_container(self.docker,case,record['request'],runtime['resolved']['identity'])
        require(observed=={k:v for k,v in record.items() if k not in {'observed_at','runtime_candidate'}},'live deployment, source, launch or mounts changed')
        return record

    def offline(self,key,operation_id,stage):
        require(stage in {'c2','c5'},'unsupported offline adapter')
        case=self.case(key)
        operation=self.store.get('operation',operation_id)
        require(operation and operation['status']=='completed' and operation.get('result',{}).get('exit_code')==0,'completed successful execution required')
        auth=self.store.get('authorization',operation['authorization']);run=self.store.get('run',operation['run'])
        require(auth and run and not auth['revoked'] and run['authorization']==operation['authorization']
            and operation['specification'] in auth['spec']['operations'] and operation['finished_at']<=auth['spec']['limits']['expires_at']
            and self.clock()<auth['spec']['limits']['expires_at'],'offline authority unavailable')
        spec=operation['specification']
        require(spec['entrypoint']=='scripts/'+stage+'_worker.py' and spec['interpreter']=='python' and spec['arguments']==[], 'not the selected adapter')
        controller=self.traffic.controller;controller.docker=self.docker
        worker=controller.candidate(run['bindings'][spec['component']])
        require(worker['kind']=='tool' and worker['manifest']==selected_tree(self.package,['scripts']),'adapter differs from current package')
        require(set(run['bindings'])=={'head','runtime'}|set(auth['spec']['components']),'component closure differs')
        bindings={}
        for component,candidate_id in run['bindings'].items():
            candidate=controller.check_current(candidate_id)
            controller.reviewed(candidate_id,candidate,self.store)
            bindings[component]=digest(candidate)
        self.traffic.fresh_head()
        require({p:sha256(read_file(auth['spec']['root'],p,64*1024**2)) for p in auth['manifest']}==auth['manifest'],'authorized inputs changed')
        raw=read_file(self.store.root,operation_id+'.output',spec['max_output_bytes'])
        require(sha256(raw)==operation['result']['sha256'] and len(raw)==operation['result']['bytes'],'output bytes differ')
        value=parse(raw,8*1024**2)
        require(value.get('schema_version')==1 and value.get('adapter')=={'c2':'c2-trivy-npm','c5':'c5-cosign-public-key'}[stage],'unsupported adapter report')
        tool_id='trivy' if stage=='c2' else 'cosign'
        require(tool_id in run['bindings'],'tool producer missing')
        tool=controller.candidate(run['bindings'][tool_id]);source=controller.source(tool_id)
        require(source['repository']=={'c2':'aquasecurity/trivy','c5':'sigstore/cosign'}[stage]
                and set(tool['manifest'])=={tool_id},'unsupported tool source')
        if stage=='c2':
            require(set(auth['manifest'])=={'package-lock.json'} and case['source'] and auth['spec']['root']==case['source']['root']
                and case['source']['manifest'].get('package-lock.json')==auth['manifest']['package-lock.json'],'dependency scope differs')
            require(value['inventory']['input_sha256']==auth['manifest']['package-lock.json'] and value['tool_version']==tool['resolved']['identity']['label'].removeprefix('v'),'observed inventory/tool differs')
            require('trivy-db' in run['bindings'],'independent advisory data missing')
            data=controller.candidate(run['bindings']['trivy-db']);data_spec=controller.source('trivy-db')
            require(data_spec.get('provider')=='trivy-db-oci','unsupported advisory source')
            metadata=read_file(self.store.root/'objects'/run['bindings']['trivy-db'],'db/metadata.json',16384)
            require(value['data_metadata']==validate_metadata(metadata,data_spec,self.clock(),data['resolved']['identity']['published_at']),'actual advisory metadata differs')
        else:
            require(set(auth['manifest'])=={'artifact.bin','attestation.json','attestation.bundle.json'},'provenance input closure differs')
            require('publisher-policy' in run['bindings'],'independent publisher policy missing')
            require(value['facts']['artifact_sha256']==auth['manifest']['artifact.bin'] and value['facts']['attestation_sha256']==auth['manifest']['attestation.json'],'signed bytes differ')
            require(case['scope']['source'] and value['facts']['source_revision']==case['scope']['source']['revision'],'provenance source revision differs from assessment')
            version=value['tool_version']
            require(isinstance(version,dict) and version.get('gitVersion',version.get('GitVersion'))==tool['resolved']['identity']['label'],'observed verifier version differs')
        record={'assessment':key,'scope_sha256':case['scope_sha256'],'stage':stage,'operation':operation_id,'operation_sha256':digest(operation),
            'bindings':bindings,'output_sha256':sha256(raw),'report':value,'recorded_at':self.clock()}
        with self.store.transaction() as tx:
            require(tx.get('checklist-execution',operation_id) is None,'execution already retained')
            tx.put('checklist-execution',operation_id,record)
        return {'operation':operation_id,'stage':stage,'outcome':value['outcome'],'checklist_item_outcomes':'unverified-until-complete-item-evidence'}

    def bind_deployment(self,key,spec):
        require(self.docker is not None,'local Docker required')
        case=self.case(key);self.traffic.fresh_head()
        controller=self.traffic.controller;controller.docker=self.docker
        runtime_id=self.store.get('active','runtime');require(runtime_id,'current reviewed runtime required')
        runtime=controller.check_current(runtime_id);controller.reviewed(runtime_id,runtime,self.store)
        value=inspect_container(self.docker,case,spec,runtime['resolved']['identity'])
        value['observed_at']=self.clock()
        value['runtime_candidate']=runtime_id
        with self.store.transaction() as tx:
            require(tx.get('deployment-binding',spec['id']) is None,'deployment binding ID cannot be reused')
            tx.put('deployment-binding',spec['id'],value)
        return {'binding':spec['id'],'outcome':value['outcome'],'checks':value['checks'],'limits':value['limits']}

    def backup_access(self,key,recovery_id,binding_id):
        require(self.docker is not None,'local Docker required')
        case=self.case(key);self.traffic.fresh_head()
        recovery=self.store.get('service-recovery',recovery_id);binding=self.store.get('deployment-binding',binding_id)
        require(recovery and binding and recovery['assessment']==binding['assessment']==key,'backup/application identity unavailable')
        info=self.docker.inspect(binding['container'])
        require(info and info['Image']==binding['image'] and info['State']['StartedAt']==binding['started_at'] and info['State']['Running'],'application identity changed')
        user=info['Config'].get('User')
        require(user=='65532:65532','qualified unprivileged application identity required')
        # Probe only the selected backup path with the actual application UID in
        # its existing namespace. No target script, content output or mutation.
        backup=(self.store.root/recovery['backup']).resolve(strict=True)
        matches=[]
        require(not info['HostConfig'].get('Binds'),'ambiguous legacy mounts are unsupported')
        for mount in info['HostConfig'].get('Mounts',[]):
            if mount.get('Type')!='bind':continue
            source=Path(mount['Source']).resolve(strict=True)
            if backup==source or backup.is_relative_to(source):
                relative=backup.relative_to(source).as_posix()
                matches.append(mount['Target'].rstrip('/')+('' if relative=='.' else '/'+relative))
        require(len(matches)<=1,'ambiguous backup exposure')
        path=matches[0] if matches else '/__cybersecurity_unmounted_backup__/'+recovery['backup']
        probe='import os,sys,json\ntry:\n f=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW);os.close(f);print("true")\nexcept OSError:print("false")'
        result=self.docker.command(['exec','--user',user,binding['container'],'/usr/local/bin/python','-I','-B','-c',probe,path],timeout=10,limit=128)
        require(result['exit_code']==0 and result['content'].strip() in {b'true',b'false'},'backup access attempt unavailable')
        operation='backup-access-'+secrets.token_hex(16)
        record={'assessment':key,'binding':binding_id,'binding_sha256':digest(binding),'backup_sha256':recovery['backup_sha256'],
                'read_succeeded':result['content'].strip()==b'true','observed_at':self.clock(),'container':binding['container'],'user':user,
                'namespace_path_sha256':sha256(path.encode()),'mounts_sha256':digest(info['HostConfig'].get('Mounts',[])),'backup_mounted':bool(matches)}
        with self.store.transaction() as tx:tx.put('backup-access-operation',operation,record)
        return {'operation':operation,'outcome':'failed' if record['read_succeeded'] else 'satisfied','claim':'Selected backup access in this actual application namespace only.'}

    def pipeline_observe(self,key,expected,github):
        case=self.case(key);head=self.traffic.fresh_head()
        result=pipeline(github,expected)
        operation='pipeline-'+secrets.token_hex(16)
        with self.store.transaction() as tx:
            tx.put('pipeline-operation',operation,{'assessment':key,'scope_sha256':case['scope_sha256'],
                'head':head,'observed_at':self.clock(),'expected':expected,'result':result})
        return {'operation':operation,**result}

    def execution_report(self,key):
        """Historical private observations. Never promotes an item or a stale pass."""
        from .checklist_report import build_report
        case=self.case(key)
        return build_report(self,case)
