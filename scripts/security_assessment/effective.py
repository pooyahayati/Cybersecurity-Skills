"""Read effective local container settings and bind source to its launch configuration."""

import re

from security_runtime.common import digest,fields,identifier,read_file,require,sha256,portable_tree,relpath,parse
from security_runtime.web_scope import url


def inspect_container(docker,case,spec,runtime_identity):
    fields(spec,{'id','deployment','container','source_mount','database_mount','entrypoint','command'})
    identifier(spec['id'])
    require(spec['source_mount']=='/app' and spec['database_mount']=='/tmp/application.sqlite3',
            'fixed non-system source and database mount targets required')
    require(re.fullmatch(r'[0-9a-f]{64}',spec['container']),'exact container identity required')
    deployment=next((d for d in case['scope']['deployments'] if d['id']==spec['deployment']),None)
    require(deployment and case['source'],'source and deployment required')
    info=docker.inspect(spec['container']);require(info and info['Id']==spec['container'] and info['State']['Running'],'running exact container unavailable')
    config=info['Config'];host=info['HostConfig']
    require(info['Image']==runtime_identity['image_id'],'service does not use the independently reviewed runtime image')
    image=parse(docker.checked(['image','inspect',runtime_identity['reference']]))
    require(len(image)==1 and image[0]['Id']==info['Image'] and config.get('Env',[])==image[0]['Config'].get('Env',[]),'service loader environment differs from reviewed runtime')
    require(not config.get('Volumes') and not host.get('Binds') and not host.get('VolumesFrom')
            and not host.get('Devices') and not host.get('DeviceRequests'),'unsupported executable or inherited mount surface')
    require(len(host.get('Mounts',[]))==2 and {m.get('Target') for m in host['Mounts']}=={spec['source_mount'],spec['database_mount']}
            and all(m.get('Type')=='bind' for m in host['Mounts']),'exact source/database mount closure required')
    require(not spec['database_mount'].startswith(spec['source_mount'].rstrip('/')+'/')
            and not spec['source_mount'].startswith(spec['database_mount'].rstrip('/')+'/'),'source and database mounts overlap')
    require(config.get('Entrypoint')==spec['entrypoint'] and config.get('Cmd')==spec['command'],'actual launch command differs')
    command=spec['command']
    require(spec['entrypoint']==['/usr/local/bin/python'] and isinstance(command,list) and len(command) in {6,8}
            and command[:2]==['-I','-B'] and command[4]=='--port' and command[5].isdecimal()
            and (len(command)==6 or command[6:]==['--host','0.0.0.0']), 'unsupported isolated Python service launch profile')
    require(deployment['artifact']==info['Image'],'deployed image differs from assessment')
    require(isinstance(spec['source_mount'],str) and spec['source_mount'].startswith('/') and '..' not in spec['source_mount'].split('/'),'invalid source mount')
    matches=[m for m in host.get('Mounts',[]) if m.get('Target')==spec['source_mount']]
    require(len(matches)==1 and matches[0].get('Type')=='bind' and matches[0].get('ReadOnly') is True
            and matches[0].get('Source')==case['source']['root'],'read-only exact captured source mount required')
    require(command[2].startswith(spec['source_mount'].rstrip('/')+'/'),'launch entrypoint does not use captured source')
    entrypoint=command[2][len(spec['source_mount'].rstrip('/'))+1:];relpath(entrypoint)
    require(entrypoint.endswith('.py') and entrypoint in case['source']['manifest'],'source entrypoint is not captured')
    require(portable_tree(case['source']['root'],128*1024**2)==case['source']['manifest'],'whole launched source tree differs from capture')
    effective=[m for m in info.get('Mounts',[]) if m.get('Destination')==spec['source_mount']]
    require(len(effective)==1 and effective[0].get('RW') is False and effective[0].get('Type')=='bind'
            and len(info.get('Mounts',[]))==2 and {m.get('Destination') for m in info['Mounts']}=={spec['source_mount'],spec['database_mount']},'effective mount closure differs')
    user=config.get('User','')
    scheme,hostname,port,_=url(deployment['url'])
    published=info.get('NetworkSettings',{}).get('Ports',{}).get(command[5]+'/tcp') or []
    url_binding=scheme=='http' and hostname=='127.0.0.1' and any(row.get('HostIp')=='127.0.0.1' and row.get('HostPort')==str(port) for row in published)
    database_host_path=None
    if spec['database_mount']:
        matches=[m for m in host.get('Mounts',[]) if m.get('Target')==spec['database_mount'] and m.get('Type')=='bind']
        require(len(matches)==1 and command[3]==spec['database_mount'],'exact mounted database in launch command required')
        database_host_path=matches[0]['Source']
    require(database_host_path,'mounted service database is required')
    checks={'non_root':user=='65532:65532','read_only_root':host.get('ReadonlyRootfs') is True,
        'not_privileged':host.get('Privileged') is False,'capabilities_dropped':host.get('CapDrop')==['ALL'] and not host.get('CapAdd'),
        'no_privilege_escalation':'no-new-privileges=true' in host.get('SecurityOpt',[]) or 'no-new-privileges' in host.get('SecurityOpt',[]),
        'no_host_network':host.get('NetworkMode') in {'bridge','default'},'no_host_namespaces':host.get('PidMode','')!='host' and host.get('IpcMode','')!='host',
        'resource_limits':host.get('Memory',0)>0 and host.get('PidsLimit',0)>0,
        'only_authorized_loopback_service':url_binding and host.get('PortBindings')=={command[5]+'/tcp':[{'HostIp':'127.0.0.1','HostPort':str(port)}]}}
    return {'assessment':case['scope']['id'],'scope_sha256':case['scope_sha256'],'deployment':spec['deployment'],
            'source_sha256':digest(case['source']['manifest']),'container':info['Id'],'image':info['Image'],'started_at':info['State']['StartedAt'],
            'launch_sha256':digest({'entrypoint':config.get('Entrypoint'),'command':config.get('Cmd'),'mounts':host.get('Mounts')}),
            'url_binding_verified':url_binding,'database_host_path':database_host_path,
            'source_binding_verified':all(checks[k] for k in ('non_root','read_only_root','not_privileged','capabilities_dropped','no_privilege_escalation','no_host_namespaces')),
            'request':spec,'environment_sha256':digest(config.get('Env',[])),
            'checks':checks,'outcome':'satisfied' if all(checks.values()) else 'failed',
            'limits':['Selected Python service launch, bounded privilege and exact approved loopback exposure only. Outbound segmentation, host firewall and remote database/web-server settings remain unverified.']}


def pipeline(github,expected):
    fields(expected,{'repository','repository_id','owner_id'})
    repository=expected['repository']
    require(isinstance(repository,str) and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repository),'invalid repository')
    metadata=github.json(repository)
    require(metadata.get('id')==expected['repository_id'] and metadata.get('owner',{}).get('id')==expected['owner_id']
            and metadata.get('full_name','').casefold()==repository.casefold(),'hosted repository identity differs')
    permissions=github.json(repository+'/actions/permissions/workflow')
    require(permissions.get('default_workflow_permissions') in {'read','write'} and type(permissions.get('can_approve_pull_request_reviews')) is bool,'hosted effective permissions unavailable')
    checks={'default_token_read_only':permissions['default_workflow_permissions']=='read',
            'workflow_cannot_approve_pr':permissions['can_approve_pull_request_reviews'] is False}
    return {'repository':repository,'repository_id':metadata['id'],'facts':permissions,'checks':checks,
            'outcome':'satisfied' if all(checks.values()) else 'failed','limits':['Selected effective Actions defaults only; per-job grants, environments, branch rules and runner isolation remain separate checks.']}
