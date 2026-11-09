#!/usr/bin/env python3
"""C2-C6 current-tool, traffic, application, provenance and recovery evidence."""

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from m2_assess import document
from security_assessment.checklist_runtime import ChecklistReview
from security_assessment.effective import pipeline
from security_runtime.common import fields,read_file,require
from security_runtime.private import private_directory
from security_runtime.sandbox import Docker
from security_runtime.sources import GitHub,Http
from security_runtime.store import Store


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',required=True,type=Path);parser.add_argument('--docker',type=Path)
    parser.add_argument('--token-env',help='Explicit environment variable containing an authorized GitHub read token; never persisted.')
    commands=parser.add_subparsers(dest='command',required=True)
    commands.add_parser('init');commands.add_parser('create').add_argument('file',type=Path)
    for name in ('authorize','scenario-plan','bind-deployment','detection-plan','backup-capture','pipeline'):
        command=commands.add_parser(name);command.add_argument('assessment');command.add_argument('file',type=Path)
    for name in ('dependency-import','provenance-import'):
        command=commands.add_parser(name);command.add_argument('assessment');command.add_argument('operation')
    for name in ('request','navigate','scenario-exercise'):
        command=commands.add_parser(name);command.add_argument('assessment');command.add_argument('authorization')
        if name!='scenario-exercise':command.add_argument('route')
        command.add_argument('--credentials',type=Path);command.add_argument('--ca',type=Path);command.add_argument('--body',type=Path)
    commands.add_parser('cancel').add_argument('authorization')
    commands.add_parser('report').add_argument('assessment')
    command=commands.add_parser('scenario-compare');command.add_argument('original');command.add_argument('candidate')
    commands.add_parser('zap-prepare');commands.add_parser('zap-review').add_argument('file',type=Path)
    command=commands.add_parser('zap-analyze');command.add_argument('assessment');command.add_argument('candidate');command.add_argument('operations',nargs='+')
    command=commands.add_parser('detection-check');command.add_argument('assessment');command.add_argument('exercise');command.add_argument('file',type=Path)
    command=commands.add_parser('detection-listen');command.add_argument('assessment');command.add_argument('exercise')
    command=commands.add_parser('backup-restore');command.add_argument('assessment');command.add_argument('recovery')
    command=commands.add_parser('backup-access');command.add_argument('assessment');command.add_argument('recovery');command.add_argument('binding')
    command=commands.add_parser('recovery-check');command.add_argument('assessment');command.add_argument('recovery');command.add_argument('file',type=Path)
    try:
        parser.error=lambda message:(_ for _ in ()).throw(ValueError('invalid command'))
        args=parser.parse_args(argv);package=Path(__file__).resolve().parents[1]
        store=Store(args.state,package,initialize=args.command=='init')
        require(args.docker is None or args.docker.is_absolute(),'absolute Docker executable required')
        docker=Docker(args.docker,store) if args.docker else None
        control=ChecklistReview(store,package,docker=docker)
        case=control.case(args.assessment) if hasattr(args,'assessment') else None
        credentials,ca,body=None,None,None
        if getattr(args,'credentials',None):
            path=args.credentials.absolute();require(path.is_relative_to(store.root),'credentials must stay in private control state')
            private_directory(path.parent);credentials=document(path)
        if getattr(args,'body',None):
            path=args.body.absolute();require(path.is_relative_to(store.root),'request payload must stay in private control state')
            private_directory(path.parent);body=read_file(path.parent,path.name,1024*1024)
        if getattr(args,'ca',None):ca=read_file(args.ca.absolute().parent,args.ca.name,4096).decode('ascii')
        name=args.command
        if name=='init':result={'status':'initialized'}
        elif name=='create':result=control.create(document(args.file))
        elif name=='authorize':result=control.traffic.authorize(case,document(args.file))
        elif name=='request':result=control.traffic.execute(case,args.authorization,args.route,body or b'',credentials,ca)
        elif name=='navigate':
            require(body is None,'navigation payload unsupported');result=control.traffic.navigate(case,args.authorization,args.route,credentials,ca)
        elif name=='cancel':result=control.traffic.cancel(args.authorization)
        elif name in {'dependency-import','provenance-import'}:result=control.offline(args.assessment,args.operation,'c2' if name=='dependency-import' else 'c5')
        elif name=='scenario-plan':result=control.traffic.plan(case,document(args.file))
        elif name=='scenario-exercise':
            from security_runtime.common import parse,canonical
            bodies={key:canonical(value) for key,value in parse(body).items()} if body else {}
            result=control.traffic.exercise(case,args.authorization,bodies,credentials,ca)
        elif name=='scenario-compare':result=control.traffic.compare(args.original,args.candidate)
        elif name=='bind-deployment':result=control.bind_deployment(args.assessment,document(args.file))
        elif name=='pipeline':
            require(args.token_env and args.token_env in os.environ,'explicit authorized GitHub read credential required')
            result=control.pipeline_observe(args.assessment,document(args.file),GitHub(Http(os.environ[args.token_env])))
        elif name=='report':result=control.execution_report(args.assessment)
        elif name=='zap-prepare':result=control.zap.prepare()
        elif name=='zap-review':result=control.zap.review(document(args.file))
        elif name=='zap-analyze':result=control.zap.analyze(case,args.candidate,args.operations)
        elif name=='detection-plan':result=control.service_recovery.plan_detection(case,document(args.file))
        elif name=='detection-listen':result=control.service_recovery.listen(case,args.exercise)
        elif name=='detection-check':
            value=document(args.file);fields(value,{'paths','trigger_operation'})
            result=control.service_recovery.detection(case,args.exercise,**value)
        elif name=='backup-capture':result=control.service_recovery.capture(case,document(args.file))
        elif name=='backup-restore':result=control.service_recovery.restore(case,args.recovery)
        elif name=='backup-access':result=control.backup_access(args.assessment,args.recovery,args.binding)
        elif name=='recovery-check':
            value=document(args.file);fields(value,{'positive','compromised','backup_access','service_binding'})
            result=control.service_recovery.finish(case,args.recovery,**value)
        print(json.dumps(result,allow_nan=False));return 0
    except Exception:
        print('{"status":"blocked","reason":"Required scope, current resources, independent evidence or execution controls are unavailable. Inspect private retained state; no security pass is established."}')
        return 1


if __name__=='__main__':raise SystemExit(main())
