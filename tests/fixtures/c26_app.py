"""Owned disposable HTTP/SQLite application. Synthetic data only; never deploy."""

import argparse
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import time
from urllib.request import build_opener,ProxyHandler,Request

MODE='fixed'  # Qualification builds exact original/candidate source variants.


def initialize(path):
    with sqlite3.connect(path) as db:
        db.executescript('''
          CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY,tenant TEXT,resets INTEGER);
          CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,account TEXT,revoked INTEGER);
          CREATE TABLE IF NOT EXISTS documents(id INTEGER PRIMARY KEY,owner TEXT,tenant TEXT,value INTEGER,reads INTEGER);
          CREATE TABLE IF NOT EXISTS uploads(name TEXT,content TEXT);
          CREATE TABLE IF NOT EXISTS payments(event TEXT,amount INTEGER);
          CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY AUTOINCREMENT,intent TEXT UNIQUE,owner TEXT,amount INTEGER);
          CREATE TABLE IF NOT EXISTS balance(id INTEGER PRIMARY KEY,value INTEGER);
          CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY,generation INTEGER);
          CREATE TABLE IF NOT EXISTS customers(id INTEGER PRIMARY KEY,owner TEXT,data TEXT);
          CREATE TABLE IF NOT EXISTS copies(id INTEGER PRIMARY KEY,data TEXT);
          CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,data TEXT);
          CREATE TABLE IF NOT EXISTS audit_config(id INTEGER PRIMARY KEY,data TEXT);
          CREATE TABLE IF NOT EXISTS audit_events(id TEXT PRIMARY KEY,data TEXT);
        ''')
        if not db.execute('SELECT count(*) FROM accounts').fetchone()[0]:
            db.executemany('INSERT INTO accounts VALUES (?,?,0)',[('alice','one'),('bob','one'),('carol','two')])
            db.executemany('INSERT INTO sessions VALUES (?,?,0)',[(x+'-session',x) for x in ('alice','bob','carol')])
            db.executemany('INSERT INTO documents VALUES (?,?,?,0,0)',[(1,'alice','one'),(2,'bob','one'),(3,'carol','two')])
            db.execute('INSERT INTO balance VALUES (1,0)');db.execute('INSERT INTO settings VALUES (1,1)')
            db.executemany('INSERT INTO customers VALUES (?,?,?)',[(1,'alice','synthetic-one'),(2,'carol','synthetic-two')])
            db.executemany('INSERT INTO copies VALUES (?,?)',[(1,'synthetic-one'),(2,'synthetic-two')])
            db.execute('INSERT INTO events VALUES (1,"synthetic-first")')


def serve(path,port,host):
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*args):pass
        def reply(self,status,value):
            raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
            self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)))
            self.end_headers();self.wfile.write(raw)
        def do_GET(self):self.handle_request({})
        def do_POST(self):
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=65536:return self.reply(413,{'error':'size'})
            try:value=json.loads(self.rfile.read(size))
            except Exception:return self.reply(400,{'error':'json'})
            self.handle_request(value)
        def handle_request(self,value):
            if MODE=='deny-all':return self.reply(403,{'error':'denied'})
            fixed=MODE=='fixed'
            token=self.headers.get('Authorization','').removeprefix('Bearer ')
            db=sqlite3.connect(path,timeout=3)
            db.execute('PRAGMA foreign_keys=ON');db.execute('PRAGMA trusted_schema=OFF')
            try:
                db.execute('BEGIN IMMEDIATE')
                session=db.execute('SELECT account,revoked FROM sessions WHERE token=?',(token,)).fetchone()
                actor=session[0] if session and (not fixed or not session[1]) else None
                status,out=200,{'ok':True}
                if self.path=='/health':out={'ready':True}
                elif self.path=='/identity':
                    if actor:out={'account':actor,'tenant':db.execute('SELECT tenant FROM accounts WHERE id=?',(actor,)).fetchone()[0]}
                    elif token in {'owned-old-key','owned-new-key'}:out={'principal':'integration'}
                    else:status,out=403,{'error':'denied'}
                elif self.path=='/state':
                    generation=db.execute('SELECT generation FROM settings').fetchone()[0]
                    if token!='recovery-new' and (fixed and generation==2 or token!='recovery-old'):status,out=403,{'error':'denied'}
                    else:out={'events':[list(r) for r in db.execute('SELECT id,data FROM events ORDER BY id')]}
                elif self.path=='/audit-exercise':
                    config=json.loads(db.execute('SELECT data FROM audit_config WHERE id=1').fetchone()[0])
                    if value!=config['event']:status,out=403,{'error':'denied'}
                    else:
                        expected=config['expected']
                        row={'exercise':expected['exercise'],'event':expected['event'],'hop':'target',
                            'previous_sha256':expected['event_sha256'],'observed_at':time.time(),'owner':expected['owner']}
                        encoded=json.dumps(row,sort_keys=True,separators=(',',':')).encode()
                        row['mac']=hmac.new(bytes.fromhex(config['target_key']),encoded,'sha256').hexdigest()
                        encoded=json.dumps(row,sort_keys=True,separators=(',',':'))
                        db.execute('INSERT INTO audit_events VALUES (?,?)',(expected['exercise'],encoded));db.commit()
                        opener=build_opener(ProxyHandler({}))
                        with opener.open(Request(config['collector'],data=('['+encoded+']').encode(),headers={'Content-Type':'application/json'},method='POST'),timeout=3) as response:
                            if response.status!=204:raise RuntimeError('collector unavailable')
                        out={'audit_event':row}
                elif self.path=='/account/recovery':
                    valid=value.get('account')=='bob' and value.get('recovery')=='owned-recovery-proof' and value.get('mfa')=='owned-second-factor'
                    if fixed and not valid:status,out=403,{'error':'denied'}
                    else:db.execute('UPDATE accounts SET resets=resets+1 WHERE id=?',(value.get('account'),))
                elif self.path=='/sessions/revoke':
                    if actor!='alice':status,out=403,{'error':'denied'}
                    elif fixed:db.execute('UPDATE sessions SET revoked=1 WHERE account="alice"')
                elif self.path=='/documents/read':
                    if not actor:status,out=403,{'error':'denied'}
                    else:
                        db.execute('UPDATE documents SET reads=reads+1 WHERE id=1')
                        out={'private':'owned-synthetic-record'}
                elif self.path=='/documents/update':
                    row=db.execute('SELECT owner,tenant FROM documents WHERE id=?',(value.get('id'),)).fetchone()
                    if fixed and (not row or row[0]!=actor or set(value)!={'id','value'}):status,out=403,{'error':'denied'}
                    else:db.execute('UPDATE documents SET value=? WHERE id=?',(value.get('value'),value.get('id')))
                elif self.path=='/files/upload':
                    name=value.get('name','');content=value.get('content','')
                    valid=actor=='alice' and name.endswith('.txt') and '/' not in name and '\\' not in name and len(content)<=64
                    if fixed and not valid:status,out=403,{'error':'denied'}
                    else:db.execute('INSERT INTO uploads VALUES (?,?)',(name,content))
                elif self.path=='/webhooks/payment':
                    event=value.get('event');amount=value.get('amount');stamp=value.get('timestamp',0)
                    signed=json.dumps({'event':event,'amount':amount,'timestamp':stamp},sort_keys=True,separators=(',',':')).encode()
                    expected=hmac.new(b'owned-synthetic-webhook-key',signed,'sha256').hexdigest()
                    if fixed and (not hmac.compare_digest(str(value.get('signature','')),expected) or abs(time.time()-stamp)>60):status,out=403,{'error':'denied'}
                    elif fixed and db.execute('SELECT 1 FROM payments WHERE event=?',(event,)).fetchone():status,out=409,{'error':'replay'}
                    else:db.execute('INSERT INTO payments VALUES (?,?)',(event,amount))
                elif self.path=='/transactions/create':
                    intent=value.get('intent');amount=value.get('amount')
                    existing=db.execute('SELECT owner,amount FROM transactions WHERE intent=?',(intent,)).fetchone()
                    if fixed and (not actor or existing and existing!=(actor,amount)):status,out=422,{'error':'intent-conflict'}
                    elif fixed and existing:out={'ok':True,'replayed':True}
                    else:
                        db.execute('UPDATE balance SET value=value+? WHERE id=1',(amount,))
                        db.execute('INSERT INTO transactions(intent,owner,amount) VALUES (?,?,?)',(intent if fixed else str(time.time_ns()),actor,amount))
                elif self.path=='/secrets/rotate':
                    if actor!='alice':status,out=403,{'error':'denied'}
                    else:db.execute('UPDATE settings SET generation=2 WHERE id=1')
                elif self.path=='/secrets/use':
                    generation=db.execute('SELECT generation FROM settings').fetchone()[0]
                    if token!='owned-new-key' and (fixed and generation==2 or token!='owned-old-key'):status,out=403,{'error':'denied'}
                    else:db.execute('UPDATE balance SET value=value+1 WHERE id=1')
                elif self.path=='/customers/delete':
                    row=db.execute('SELECT owner FROM customers WHERE id=?',(value.get('id'),)).fetchone()
                    if fixed and (not row or row[0]!=actor):status,out=403,{'error':'denied'}
                    else:
                        db.execute('DELETE FROM customers WHERE id=?',(value.get('id'),))
                        if fixed:db.execute('DELETE FROM copies WHERE id=?',(value.get('id'),))
                else:status,out=404,{'error':'missing'}
                db.commit()
                if MODE=='deny-after-write' and self.path not in {'/health','/identity'}:status,out=403,{'error':'denied'}
                self.reply(status,out)
            except Exception:
                db.rollback();self.reply(500,{'error':'unavailable'})
            finally:db.close()
    server=ThreadingHTTPServer((host,port),Handler)
    server.daemon_threads=True
    server.serve_forever()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('database',type=Path);parser.add_argument('--port',type=int,default=8080);parser.add_argument('--host',default='127.0.0.1')
    args=parser.parse_args();initialize(args.database);serve(args.database,args.port,args.host)
