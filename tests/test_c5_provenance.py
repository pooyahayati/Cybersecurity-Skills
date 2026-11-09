import copy
import unittest

from security_assessment.provenance import match
from security_assessment.effective import pipeline
from security_runtime.common import Blocked,canonical,sha256


class ProvenanceTests(unittest.TestCase):
    def fixture(self):
        artifact=b'owned artifact';key=b'owned reviewed public key'
        policy={'schema_version':1,'publisher':'Owned fixture','key_sha256':sha256(key),'artifact_name':'fixture.bin',
            'predicate_type':'https://slsa.dev/provenance/v1','builder':'owned-builder','source_uri':'https://example.invalid/owned',
            'source_revision':'a'*40,'workflow':'owned-build'}
        statement={'_type':'https://in-toto.io/Statement/v1','subject':[{'name':'fixture.bin','digest':{'sha256':sha256(artifact)}}],
            'predicateType':policy['predicate_type'],'predicate':{'buildDefinition':{'buildType':'owned-build',
            'resolvedDependencies':[{'uri':policy['source_uri'],'digest':{'gitCommit':'a'*40}}]},'runDetails':{'builder':{'id':'owned-builder'}}}}
        return artifact,key,policy,statement
    def test_independent_publisher_and_exact_build_policy(self):
        artifact,key,policy,statement=self.fixture()
        result=match(canonical(statement),artifact,key,policy)
        self.assertEqual(result['source_revision'],'a'*40);self.assertFalse(result['transparency_verified'])
        changes=[lambda p:p['subject'][0]['digest'].update(sha256='0'*64),lambda p:p['predicate']['runDetails']['builder'].update(id='other'),
            lambda p:p['predicate']['buildDefinition'].update(buildType='other'),lambda p:p['predicate']['buildDefinition']['resolvedDependencies'][0]['digest'].update(gitCommit='b'*40)]
        for change in changes:
            bad=copy.deepcopy(statement);change(bad)
            with self.assertRaises(Blocked):match(canonical(bad),artifact,key,policy)
        with self.assertRaises(Blocked):match(canonical(statement),artifact+b'x',key,policy)
        with self.assertRaises(Blocked):match(canonical(statement),artifact,b'wrong-key',policy)
        with self.assertRaises(Blocked):match(b'{"subject":[],"subject":[]}',artifact,key,policy)
    def test_effective_hosted_permissions_preserve_safe_near_match(self):
        expected={'repository':'owned/example','repository_id':1,'owner_id':2}
        class API:
            permissions={'default_workflow_permissions':'read','can_approve_pull_request_reviews':False}
            def json(self,path):
                return {'id':1,'owner':{'id':2},'full_name':'owned/example'} if path=='owned/example' else self.permissions
        api=API();self.assertEqual(pipeline(api,expected)['outcome'],'satisfied')
        api.permissions={'default_workflow_permissions':'write','can_approve_pull_request_reviews':True}
        self.assertEqual(pipeline(api,expected)['outcome'],'failed')
        api.permissions={}
        with self.assertRaises(Blocked):pipeline(api,expected)
        with self.assertRaises(Blocked):pipeline(api,{**expected,'repository_id':3})


if __name__=='__main__':unittest.main()
