"""Publisher-key provenance policy; signature validity alone never passes."""

from security_runtime.common import fields, parse, require, sha256, text
from security_runtime.web_scope import fingerprint


def policy(value):
    fields(value, {'schema_version','publisher','key_sha256','artifact_name','predicate_type','builder','source_uri','source_revision','workflow'})
    require(value['schema_version']==1,'unsupported provenance policy')
    fingerprint(value['key_sha256'])
    for key in ('publisher','artifact_name','predicate_type','builder','source_uri','source_revision','workflow'): text(value[key],512)
    require(value['predicate_type']=='https://slsa.dev/provenance/v1','unsupported attestation type')
    return value


def match(raw, artifact, key, expected):
    policy(expected)
    require(sha256(key)==expected['key_sha256'],'publisher key differs from independently reviewed policy')
    value=parse(raw,1024*1024)
    fields(value,{'_type','subject','predicateType','predicate'})
    require(value['_type']=='https://in-toto.io/Statement/v1' and value['predicateType']==expected['predicate_type'],'statement type differs')
    require(value['subject']==[{'name':expected['artifact_name'],'digest':{'sha256':sha256(artifact)}}],'signed subject differs from actual artifact')
    predicate=value['predicate']
    fields(predicate,{'buildDefinition','runDetails'})
    definition=predicate['buildDefinition']; details=predicate['runDetails']
    require(isinstance(definition,dict) and isinstance(details,dict),'invalid provenance')
    require(details.get('builder',{}).get('id')==expected['builder'],'builder differs')
    require(definition.get('buildType')==expected['workflow'],'workflow differs')
    dependencies=definition.get('resolvedDependencies')
    require(dependencies==[{'uri':expected['source_uri'],'digest':{'gitCommit':expected['source_revision']}}], 'source revision or dependency closure differs')
    return {'publisher':expected['publisher'],'key_sha256':sha256(key),'artifact_sha256':sha256(artifact),
            'attestation_sha256':sha256(raw),'builder':expected['builder'],'source_revision':expected['source_revision'],
            'profile':'approved-public-key-offline','transparency_verified':False,'keyless_identity_verified':False}
