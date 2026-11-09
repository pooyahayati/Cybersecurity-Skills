import copy
from contextlib import closing
import sqlite3
import time
import unittest
from unittest.mock import patch

from c26_support import ScenarioWorld,TABLES
from security_assessment.scenarios import snapshot
from security_runtime.common import Blocked,canonical,digest


class ScenarioTests(unittest.TestCase):
    def setUp(self):
        self.world=ScenarioWorld();self.addCleanup(self.world.close)
    def test_all_business_families_observe_real_original_and_fixed_http_and_state(self):
        for index,family in enumerate(TABLES):
            with self.subTest(family=family):
                stamp=int(time.time())
                original=self.world.run('original-'+str(index),'vulnerable',family,stamp)
                candidate=self.world.run('candidate-'+str(index),'fixed',family,stamp)
                self.assertEqual(original['outcome'],'failed',original)
                self.assertEqual(candidate['outcome'],'satisfied',candidate)
                comparison=self.world.control.traffic.compare(original['operation'],candidate['operation'])
                self.assertEqual(comparison['outcome'],'satisfied')
    def test_denial_response_cannot_hide_committed_writes(self):
        result=self.world.run('failed-fix','deny-after-write','owner-tenant-field-operation')
        record=self.world.world.state.get('scenario-operation',result['operation'])
        denied=next(r for r in record['cases'] if r['case']=='other-owner')
        self.assertTrue(denied['response_pass']);self.assertFalse(denied['state_pass'])
        self.assertEqual(result['outcome'],'failed')
    def test_unrelated_database_and_changed_live_binding_are_rejected(self):
        case,spec,bodies,credentials=self.world.prepare('owned','fixed','file-handling')
        other,_=self.world.add('unrelated','fixed')
        bad=copy.deepcopy(spec);bad['id']='wrong-database';bad['oracle']['path']=str(other.database)
        with self.assertRaises(Blocked):self.world.control.traffic.plan(case,bad)
        self.world.bindings['owned']['database_host_path']=str(other.database)
        with self.assertRaises(Blocked):self.world.control.traffic.exercise(case,'owned',bodies,credentials)
        self.assertEqual(snapshot(spec['oracle']),{'uploads':[]})
    def test_invalid_actor_and_stale_producer_do_not_get_a_security_pass(self):
        case,spec,bodies,credentials=self.world.prepare('actor','fixed','file-handling')
        credentials['alice']['value']='Bearer never-valid'
        result=self.world.control.traffic.exercise(case,'actor',bodies,credentials)
        self.assertEqual(result['outcome'],'unverified');self.assertEqual(snapshot(spec['oracle']),{'uploads':[]})
        self.world.world.publisher.unavailable=True
        with self.assertRaises(Blocked):self.world.control.traffic.compare(result['operation'],result['operation'])
    def test_compare_rejects_changed_request_semantics(self):
        original=self.world.run('before','vulnerable','owner-tenant-field-operation')
        fixed=self.world.run('after','fixed','owner-tenant-field-operation')
        store=self.world.world.state
        with store.transaction() as tx:
            auth=tx.get('traffic-authority','after');auth['spec']['routes'][1]['url']=auth['spec']['routes'][0]['url']+'-different'
            tx.put('traffic-authority','after',auth)
        with self.assertRaises(Blocked):self.world.control.traffic.compare(original['operation'],fixed['operation'])
    def test_sqlite_oracle_rejects_views_virtual_tables_and_large_output(self):
        app,_=self.world.add('oracle','fixed')
        with closing(sqlite3.connect(app.database)) as db,db:
            db.execute('CREATE VIEW disguised AS SELECT * FROM accounts')
            db.execute('CREATE VIRTUAL TABLE virtual_rows USING fts5(value)')
            db.execute('CREATE TABLE huge(value TEXT)')
            db.executemany('INSERT INTO huge VALUES (?)',[('x'*600000,),('y'*600000,)])
        for table,columns in (('disguised',['id']),('virtual_rows',['value']),('huge',['value'])):
            with self.subTest(table=table),self.assertRaises(Exception):
                snapshot({'path':str(app.database),'tables':{table:columns}})

    def test_historical_report_preserves_unfinished_and_uncertain_attempts(self):
        case,spec,bodies,credentials=self.world.prepare('unfinished','fixed','file-handling')
        traffic=self.world.control.traffic
        with patch.object(traffic,'execute',side_effect=KeyboardInterrupt),self.assertRaises(KeyboardInterrupt):
            traffic.exercise(case,'unfinished',bodies,credentials)
        with patch.object(traffic,'_request',side_effect=Blocked('owned interruption')),self.assertRaises(Blocked):
            traffic.execute(case,'unfinished','identity-alice',credentials=credentials)
        result=self.world.control.execution_report('unfinished')
        from security_runtime.common import parse
        from pathlib import Path
        report=parse(Path(result['private_report']).read_bytes())
        self.assertEqual(report['observations'][0]['execution_status'],'unfinished')
        self.assertEqual(report['observations'][0]['observed_outcome'],'unverified')
        self.assertEqual(report['traffic_attempts'][0]['status'],'uncertain')
        self.assertEqual(report['security_verdict'],'not_established')


if __name__=='__main__':unittest.main()
