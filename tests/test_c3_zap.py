import base64
import copy
import hashlib
import unittest

from workflow_package import ROOT
from security_runtime.common import Blocked
from security_runtime.zap import ADDONS,catalog,official_file


class PassiveSourceTests(unittest.TestCase):
    def test_official_content_is_bound_to_exact_commit_path_and_blob(self):
        raw=b'<metadata>owned</metadata>';revision='a'*40
        record={'type':'file','path':'ZapVersions.xml','encoding':'base64','size':len(raw),
            'sha':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'content':base64.b64encode(raw).decode()+'\n'}
        class API:
            def json(self,path):
                self.path=path;return self.record
        api=API();api.record=record
        self.assertEqual(official_file(api,revision,'ZapVersions.xml'),raw)
        self.assertEqual(api.path,'zaproxy/zap-admin/contents/ZapVersions.xml?ref='+revision)
        for changed in ({'path':'another.xml'},{'sha':'b'*40},{'size':len(raw)+1},{'type':'symlink'},{'encoding':'none'}):
            api.record={**record,**changed}
            with self.assertRaises(Blocked):official_file(api,revision,'ZapVersions.xml')
        with self.assertRaises(Blocked):official_file(api,'main','ZapVersions.xml')
    def test_addon_dependency_closure_and_observed_version_are_required(self):
        rows=['<addon_'+name+'><file>'+name+'-release-1.0.zap</file><version>1.0</version><status>release</status><hash>SHA-256:'+'a'*64+'</hash></addon_'+name+'>' for name in sorted(ADDONS)]
        raw=('<root>'+''.join(rows)+'</root>').encode()
        self.assertEqual(set(catalog(raw)),ADDONS)
        for bad in (raw.replace(b'<version>1.0</version>',b'<version>2.0</version>',1),
                    b'<!DOCTYPE x [<!ENTITY bad "x">]>'+raw,
                    raw.replace(b'</addon_automation>',b'<dependencies><addons><addon><id>unreviewed</id></addon></addons></dependencies></addon_automation>',1)):
            with self.assertRaises(Blocked):catalog(bad)


if __name__=='__main__':unittest.main()
