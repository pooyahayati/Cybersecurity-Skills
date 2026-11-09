import copy
import gzip
import io
from pathlib import Path
import tarfile
import tempfile
import time
import unittest

from workflow_package import ROOT
from security_assessment.dependencies import inventory,normalize
from security_runtime.advisory import FEED,stage_database,validate_manifest,validate_metadata
from security_runtime.common import Blocked,canonical,read_file,sha256,utc
from security_runtime.sources import source_spec


class DependenciesTests(unittest.TestCase):
    def setUp(self):
        self.now=time.time()
        self.spec={'id':'trivy-db','kind':'data','provider':'trivy-db-oci','feed':FEED,'max_download_bytes':1048576,'max_unpacked_bytes':1048576,'data_max_age_seconds':86400}
        self.metadata={'Version':2,'UpdatedAt':utc(self.now-10),'NextUpdate':utc(self.now+3600)}
        self.lock={'lockfileVersion':3,'packages':{'':{'name':'owned'},'node_modules/lodash':{'version':'4.17.20'},'node_modules/fixed/node_modules/lodash':{'version':'4.17.21'}}}

    def archive(self,rows):
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w',format=tarfile.USTAR_FORMAT) as tar:
            for name,raw,kind in rows:
                info=tarfile.TarInfo(name);info.size=len(raw);info.type=kind
                tar.addfile(info,io.BytesIO(raw))
        return gzip.compress(data.getvalue())

    def test_official_feed_and_metadata_are_independent_freshness_subjects(self):
        self.assertEqual(source_spec(self.spec),self.spec)
        for change in ({'feed':'attacker.invalid/db:2'},{'kind':'tool'},{'max_unpacked_bytes':4*1024**3+1}):
            with self.subTest(change=change),self.assertRaises(Blocked):source_spec({**self.spec,**change})
        validate_metadata(canonical(self.metadata),self.spec,self.now,self.now)
        for value in ({**self.metadata,'Version':1},{**self.metadata,'UpdatedAt':utc(self.now-90000)},
                      {**self.metadata,'NextUpdate':utc(self.now-1)}):
            with self.assertRaises(Blocked):validate_metadata(canonical(value),self.spec,self.now,self.now)
        manifest={'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','artifactType':'application/vnd.aquasec.trivy.config.v1+json',
            'layers':[{'mediaType':'application/vnd.aquasec.trivy.db.layer.v1.tar+gzip','digest':'sha256:'+'a'*64,'size':100,'annotations':{'org.opencontainers.image.title':'db.tar.gz'}}],
            'annotations':{'org.opencontainers.image.created':utc(self.now)}}
        self.assertEqual(validate_manifest(canonical(manifest),self.spec,self.now)['revision'],'sha256:'+sha256(canonical(manifest)))
        manifest['layers']*=2
        with self.assertRaises(Blocked):validate_manifest(canonical(manifest),self.spec,self.now)

    def test_streamed_database_rejects_missing_duplicate_truncated_and_special_members(self):
        rows=[('trivy.db',b'owned database bytes',tarfile.REGTYPE),('metadata.json',canonical(self.metadata),tarfile.REGTYPE)]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(strict=True)
            stage,manifest=stage_database(root,{'db.tar.gz':self.archive(rows)},self.spec,{'identity':{'published_at':self.now}},self.now)
            self.assertEqual(manifest['db/trivy.db'],sha256(b'owned database bytes'))
            self.assertEqual(read_file(stage,'db/trivy.db',1024,hash_only=True),sha256(b'owned database bytes'))
            bad=[self.archive(rows[:1]),self.archive(rows+[rows[0]]),self.archive(rows)[:-5],
                 self.archive([('../escape',b'x',tarfile.REGTYPE)]+rows),self.archive([('trivy.db',b'',tarfile.SYMTYPE),rows[1]])]
            for raw in bad:
                with self.subTest(size=len(raw)),self.assertRaises((Blocked,EOFError,tarfile.TarError)):
                    stage_database(root,{'db.tar.gz':raw},self.spec,{'identity':{'published_at':self.now}},self.now)
            self.assertFalse((root.parent/'escape').exists())

    def test_exact_vulnerable_and_fixed_instances_do_not_merge(self):
        selected=inventory(canonical(self.lock))
        report={'SchemaVersion':2,'Results':[{'Type':'npm','Target':'package-lock.json','Packages':[{'Name':'lodash','Version':v} for v in ['4.17.20','4.17.21']],
            'Vulnerabilities':[{'PkgName':'lodash','InstalledVersion':'4.17.20','VulnerabilityID':'CVE-2021-23337','Severity':'HIGH','FixedVersion':'4.17.21'}]}]}
        value=normalize(report,selected,'observed-fixture-version',self.metadata)
        self.assertEqual(value['outcome'],'failed')
        self.assertEqual(len(value['findings']),1)
        self.assertEqual(value['findings'][0]['location'],'node_modules/lodash')
        self.assertEqual(len(value['sbom']['components']),2)
        report['Results'][0]['Packages'].pop()
        with self.assertRaises(Blocked):normalize(report,selected,'fixture',self.metadata)

    def test_unsupported_versions_and_missing_scan_inventory_never_pass(self):
        for version in ('^1.2.3',None,'git+https://example.invalid/repo'):
            lock=copy.deepcopy(self.lock);lock['packages']['node_modules/lodash']['version']=version
            selected=inventory(canonical(lock));self.assertTrue(selected['gaps'])
        with self.assertRaises(Blocked):inventory(b'{"lockfileVersion":3,"lockfileVersion":2,"packages":{}}')
        with self.assertRaises(Blocked):normalize({'SchemaVersion':2,'Results':[]},inventory(canonical(self.lock)),'fixture',self.metadata)
        with self.assertRaises(Blocked):inventory(canonical({'lockfileVersion':1,'dependencies':{}}))

    def test_strict_exact_semver_keeps_unsupported_versions_unverified(self):
        for version in ('01.2.3','1.2.3-.','1.2.3-alpha..one','1.2.3-01','1.2.3+','1.2.3+'+'x'*129):
            lock={'lockfileVersion':3,'packages':{'node_modules/owned':{'version':version}}}
            selected=inventory(canonical(lock));self.assertEqual(selected['components'],[])
            self.assertEqual(normalize({'SchemaVersion':2,'Results':[]},selected,'fixture',self.metadata)['outcome'],'unverified')
        for version in ('0.0.0','1.2.3','1.2.3-alpha.1','1.2.3-0.alpha+build.007','1.2.3+000'):
            selected=inventory(canonical({'lockfileVersion':3,'packages':{'node_modules/owned':{'version':version}}}))
            self.assertEqual(selected['gaps'],[]);self.assertEqual(selected['components'][0]['version'],version)
        with self.assertRaises(Blocked):inventory(canonical({'lockfileVersion':3.0,'packages':{}}))


if __name__=='__main__':unittest.main()
