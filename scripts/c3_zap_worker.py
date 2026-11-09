#!/usr/bin/python3
"""Selected passive checks over private captured traffic; Docker network is none."""

import json
import os
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from security_runtime.common import canonical,digest,parse,read_file,require,sha256
from security_runtime.process import bounded_process


def analyze():
    policy=parse(read_file('/inputs','zap-policy.json',65536))
    har=read_file('/inputs','traffic.har',12*1024**2)
    parsed=parse(har,12*1024**2)
    require(1<=len(parsed['log']['entries'])<=32,'invalid capture')
    install=Path('/tmp/zap-install');install.mkdir()
    (install/'plugin').mkdir()
    for source in Path('/zap').iterdir():
        if source.name!='plugin':(install/source.name).symlink_to(source,target_is_directory=source.is_dir())
    for addon in policy['addons'].values():
        raw=read_file('/zap/plugin',addon['file'],64*1024**2)
        require(sha256(raw)==addon['sha256'],'selected add-on is not current marketplace bytes')
        (install/'plugin'/addon['file']).symlink_to(Path('/zap/plugin')/addon['file'])
    jar=Path('/zap')/('zap-'+policy['core']+'.jar')
    require(jar.is_file(),'core version differs')
    urls=sorted({entry['request']['url'] for entry in parsed['log']['entries']})
    plan={'env':{'contexts':[{'name':'captured','urls':urls}],
                 'parameters':{'failOnError':True,'failOnWarning':True,'progressToStdout':False}},'jobs':[
        {'type':'import','parameters':{'type':'har','fileName':'/inputs/traffic.har','sendRequests':False,'maxMessages':32}},
        {'type':'passiveScan-wait','parameters':{'maxDuration':1}},
        {'type':'report','parameters':{'template':'traditional-json','reportDir':'/tmp','reportFile':'captured.json','displayReport':False}}]}
    Path('/tmp/plan.yaml').write_bytes(canonical(plan))
    env={'PATH':'/usr/bin:/bin','HOME':'/tmp','LANG':'C.UTF-8'}
    java=bounded_process(['/usr/bin/java','-version'],env,10,16384)
    require(java['exit_code']==0,'Java identity unavailable')
    result=bounded_process(['/usr/bin/java','-Xmx768m','-Djava.awt.headless=true','-jar',str(jar),'-installdir',str(install),
        '-dir','/tmp/zap-home','-cmd','-config','autoupdate.checkOnStart=false','-config','autoupdate.downloadNewRelease=false',
        '-config','autoupdate.installAddonUpdates=false','-autorun','/tmp/plan.yaml'],env,160,1024*1024)
    require(result['exit_code']==0,'passive analysis failed')
    report=parse(read_file('/tmp','captured.json',4*1024**2),4*1024**2)
    require(str(report.get('@version'))==policy['core'],'observed core differs')
    leads=[]
    for site in report.get('site',[]):
        for alert in site.get('alerts',[]):
            require(len(leads)<1000,'alert limit exceeded')
            leads.append({'rule_id':str(alert.get('pluginid')),'risk':str(alert.get('riskcode')),'confidence':str(alert.get('confidence')),
                'count':len(alert.get('instances',[])),
                'captured_url_sha256':sorted({sha256(instance['uri'].encode()) for instance in alert.get('instances',[]) if instance.get('uri') in urls}),
                'title':str(alert.get('name',alert.get('alert','')))[:256],
                'remediation':str(alert.get('solution',''))[:4096],
                'classification':'untrusted-tool-lead-requires-independent-review'})
    return {'schema_version':1,'adapter':'c3-zap-passive','policy_sha256':digest(policy),'capture_sha256':sha256(har),
        'plan_sha256':digest(plan),'core':policy['core'],'java_identity_sha256':sha256(java['content']),'addons':policy['addons'],
        'leads':leads,'browser_execution':False,'active_scan':False,'security_verdict':'not_established'}


if __name__=='__main__':
    try:print(json.dumps(analyze(),allow_nan=False))
    except Exception:
        print('{"status":"unavailable"}')
        raise SystemExit(1)
