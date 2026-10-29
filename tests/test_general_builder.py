"""Two different applications configured through the interactive generator prompts."""
import importlib.util
import copy
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import general_builder
import master_builder

class GeneralBuilderTests(unittest.TestCase):
    def configured(self,answers,directory,name):
        with patch('builtins.input',side_effect=['10']+answers+['y','n','n','n','0']),patch.object(master_builder,'OUTPUT',Path(directory)):
            master_builder.main()
        generated=[p for p in Path(directory).glob('general_application_*.py') if not p.stem.endswith(('_server','_client'))]
        self.assertEqual(len(generated),1)
        path=generated[0]
        if "'architecture': 'tcp_client_server'" in path.read_text(encoding='utf-8'):
            self.assertTrue(path.with_name(path.stem+'_server.py').exists())
            self.assertTrue(path.with_name(path.stem+'_client.py').exists())
        report=path.with_suffix('.checklist.txt')
        result=subprocess.run([sys.executable,'-B',str(path),'--self-test'],capture_output=True,text=True,timeout=120)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('SELF-TEST PASSED',result.stdout)
        acceptance=ROOT/'exam_output'/'general_acceptance'
        acceptance.mkdir(parents=True,exist_ok=True)
        shutil.copy2(path,acceptance/(name+'.py'))
        shutil.copy2(report,acceptance/(name+'.checklist.txt'))
        for kind in ('server','client'):
            wrapper=path.with_name(path.stem+'_'+kind+'.py')
            if wrapper.exists():
                text=wrapper.read_text(encoding='utf-8').replace(path.stem,name)
                (acceptance/(name+'_'+kind+'.py')).write_text(text,encoding='utf-8')
        spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module,report

    def test_arbitrary_roles_permissions_and_pin(self):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        answers=['Parcel Desk','2',
          'parcel_code','','text','Y','1','20','','Y','Y',
          'weight','','integer','Y','0','100','N','N',
          'GCM','256','sha256','sha256','elgamal','2048','','1024','Y','512','0','30','Y',str(port),'','', '2',
          'Dispatch Scribe','submit,view,search,send,rsa_product','Y','own','','','',
          'Route Inspector','view,verify,search,decrypt,serve','N','all','parcel_code,weight','parcel_code','']
        with tempfile.TemporaryDirectory() as d:
            m,_=self.configured(answers,d,'parcels')
            app=m.Application(Path(d)/'data')
            with self.assertRaisesRegex(PermissionError,'Authenticate'):app.submit('Dispatch Scribe',{'parcel_code':'P0','weight':1})
            app.configure_pin('Dispatch Scribe','1234')
            self.assertTrue(app.authenticate('Dispatch Scribe','1234'))
            with self.assertRaises(PermissionError):app.authenticate('Dispatch Scribe','wrong')
            rid=app.submit('Dispatch Scribe',{'parcel_code':'P1','weight':7})
            self.assertEqual(app.search('Route Inspector','parcel_code','P1'),[rid])
            self.assertTrue(app.verify('Route Inspector',rid))
            self.assertEqual(app.decrypt('Route Inspector',rid,'parcel_code'),'P1')
            self.assertIn('wrapped_key',app.records()[0])
            wrapped=bytes.fromhex(app.records()[0]['wrapped_key'])
            oaep=m.asympad.OAEP(mgf=m.asympad.MGF1(m.hashes.SHA256()),algorithm=m.hashes.SHA256(),label=None)
            self.assertEqual(len(app.wrap_private.decrypt(wrapped,oaep)),32)
            self.assertTrue(app.rsa_product('Dispatch Scribe',3,7)['verified'])
            server=m.Application(Path(d)/'data')
            ready=threading.Event();out=[]
            worker=threading.Thread(target=lambda:out.append(server.serve_once('Route Inspector',ready)))
            worker.start();self.assertTrue(ready.wait(10))
            remote=app.send('Dispatch Scribe',{'parcel_code':'P2','weight':9},'1234')
            worker.join(10);self.assertFalse(worker.is_alive())
            self.assertTrue(out[0]['ok'])
            self.assertEqual(app.search('Route Inspector','parcel_code','P2'),[remote])
            server=m.Application(Path(d)/'data')
            stop=threading.Event();ready=threading.Event()
            worker=threading.Thread(target=server.serve_forever,args=('Route Inspector',ready,stop))
            worker.start();self.assertTrue(ready.wait(10))
            try:
                with ThreadPoolExecutor(max_workers=2) as clients:
                    more=list(clients.map(lambda i:app.send('Dispatch Scribe',{'parcel_code':'P'+str(i),'weight':i},'1234'),(4,5)))
                self.assertEqual(len(set(more)),2)
                with socket.create_connection(('127.0.0.1',port),timeout=3) as connection:
                    connection.sendall(m.frame_bytes({'invalid':'request'}))
                    self.assertFalse(m.read_frame(connection)['ok'])
                with socket.create_connection(('127.0.0.1',port),timeout=3) as connection:
                    connection.sendall(b'10\n{}')
                self.assertIn(more[0],app.search('Route Inspector','parcel_code','P4'))
            finally:
                stop.set();worker.join(10)
            self.assertFalse(worker.is_alive())
            app.config['roles']['Route Inspector']['condition']={'field':'weight','equals':7}
            self.assertEqual(app.search('Route Inspector','parcel_code','P2'),[])
            with self.assertRaisesRegex(PermissionError,'condition'):app.view('Route Inspector',remote)
            del app.config['roles']['Route Inspector']['condition']
            with self.assertRaisesRegex(ValueError,'Replay'):app.submit('Dispatch Scribe',{'parcel_code':'P3','weight':1},nonce=app.records()[0]['nonce'])
            stale=(datetime.now(timezone.utc)-timedelta(minutes=2)).isoformat()
            with self.assertRaisesRegex(ValueError,'Stale'):app.submit('Dispatch Scribe',{'parcel_code':'P3','weight':1},timestamp=stale)
            left,right=socket.socketpair()
            with closing(left),closing(right):
                left.sendall(b'5\nhi');left.shutdown(socket.SHUT_WR)
                with self.assertRaisesRegex(ValueError,'Incomplete'):m.read_frame(right)
            left,right=socket.socketpair()
            with closing(left),closing(right):
                left.sendall(b'no\n{}');left.shutdown(socket.SHUT_WR)
                with self.assertRaisesRegex(ValueError,'Nondecimal'):m.read_frame(right)
            with self.assertRaises(PermissionError):app.submit('Route Inspector',{'parcel_code':'P2','weight':2})
            self.assertEqual(m.Application(Path(d)/'data').view('Route Inspector',rid)['fields']['weight'],7)
            third=app.submit('Dispatch Scribe',{'parcel_code':'P3','weight':1})
            original=m.load(app.records_path,[])
            reordered=copy.deepcopy(original);reordered[0],reordered[1]=reordered[1],reordered[0]
            m.save(app.records_path,reordered)
            with self.assertRaisesRegex(ValueError,'Broken chain'):app.records()
            deleted=copy.deepcopy(original);deleted.pop(1)
            m.save(app.records_path,deleted)
            with self.assertRaisesRegex(ValueError,'Broken chain'):app.records()
            signed=copy.deepcopy(original);signed[0]['signature']['r']='0'
            signed[0]['chain_hash']=m.hashlib.sha256(m.canonical({k:v for k,v in signed[0].items() if k!='chain_hash'})).hexdigest()
            m.save(app.records_path,signed)
            with self.assertRaisesRegex(ValueError,'Invalid record signature'):app.records()
            m.save(app.records_path,original)
            self.assertTrue(app.verify('Route Inspector',third))
            for bits in (128,192,256):
                key=b'k'*(bits//8)
                for data in (b'',b'0123456789abcdef'):
                    blob=m.aes_encrypt(data,key,'GCM')
                    self.assertEqual(m.aes_decrypt(blob,key),data)
                    broken=copy.deepcopy(blob);broken['ciphertext']=f"{int(blob['ciphertext'][:2],16)^1:02x}"+blob['ciphertext'][2:]
                    with self.assertRaises(Exception):m.aes_decrypt(broken,key)

    def test_different_schema_aes_paillier_signature_aggregate(self):
        answers=['Field Samples','3',
          'batch','','text','Y','1','20','','N','Y',
          'note','','text','Y','0','1000','','Y','N',
          'quantity','','integer','Y','0','100','N','N',
          'CBC','128','sha3_256','sha512','rsa_pss','2048','quantity','1024','N','512','2','3','0','N','','','3',
          'Sample Collector','submit,view','N','own','','','',
          'Lab Analyst','view,verify,search,decrypt,aggregate,hex_dump','N','all','batch,quantity','note','',
          'Decision Curator','approve,view','N','all','','','']
        with tempfile.TemporaryDirectory() as d:
            m,_=self.configured(answers,d,'samples')
            app=m.Application(Path(d)/'data')
            a=app.submit('Sample Collector',{'batch':'B1','note':'secret','quantity':5})
            b=app.submit('Sample Collector',{'batch':'B2','note':'other','quantity':8})
            app.approve('Decision Curator',a,'approved')
            self.assertEqual(app.view('Decision Curator',a)['approval']['decision'],'approved')
            self.assertEqual(app.decrypt('Lab Analyst',a,'note'),'secret')
            self.assertEqual(app.search('Lab Analyst','batch','B2'),[b])
            with self.assertRaisesRegex(ValueError,'Insufficient'):app.aggregate('Lab Analyst',[a,b],share_indexes=[1])
            with self.assertRaisesRegex(ValueError,'duplicate|Duplicate'):app.aggregate('Lab Analyst',[a,b],share_indexes=[1,1])
            self.assertEqual(app.aggregate('Lab Analyst',[a,b],share_indexes=[1,2])['sum'],13)
            self.assertEqual(app.aggregate('Lab Analyst',[a,b],[2,3],[2,3])['sum'],34)
            self.assertIn('00000000',app.hex_dump('Lab Analyst',a,'note'))
            with self.assertRaises(ValueError):app.aggregate('Lab Analyst',[a,a])
            with self.assertRaisesRegex(ValueError,'wrap modulus'):app.aggregate('Lab Analyst',[a,b],[app.paillier['n'],1],[1,2])
            self.assertEqual(m.Application(Path(d)/'data').aggregate('Lab Analyst',[a,b],share_indexes=[1,3])['sum'],13)
            for data in (b'',b'0123456789abcdef'):
                blob=m.aes_encrypt(data,b'k'*16,'CBC')
                self.assertEqual(m.aes_decrypt(blob,b'k'*16),data)
            rows=m.load(app.records_path,[])
            original=copy.deepcopy(rows)
            rows[0]['signature']='00'
            rows[0]['chain_hash']=m.hashlib.sha256(m.canonical({k:v for k,v in rows[0].items() if k!='chain_hash'})).hexdigest()
            m.save(app.records_path,rows)
            with self.assertRaisesRegex(ValueError,'Invalid record signature'):app.records()
            rows=copy.deepcopy(original)
            rows[0]['fields']['note']['ciphertext']='00'
            m.save(app.records_path,rows)
            with self.assertRaises(ValueError):app.records()

    def test_incompatible_configurations_are_rejected(self):
        config={'title':'x','fields':[{'name':'field','type':'text','required':True,'encrypted':False}],
                'roles':{'Novel Role':{'operations':['submit'],'auth':False,'access':'all','view_fields':[],'decrypt_fields':[]}},
                'encryption':'none','aes_bits':128,'hash':'sha256','hmac_hash':'sha256','signature':'none',
                'rsa_bits':2048,'aggregate_field':None,'paillier_bits':1024,'key_wrapping':False,
                'elgamal_bits':512,'shamir':None,'freshness_seconds':0,'textbook_rsa':False,'tcp_port':None}
        for update in ({'key_wrapping':True},{'shamir':{'threshold':2,'shares':3}},
                       {'signature':'unsupported'},{'tcp_port':80},{'freshness_seconds':-1},{'architecture':'udp_client_server'}):
            candidate=copy.deepcopy(config);candidate.update(update)
            with self.assertRaises(ValueError):general_builder.validate_config(candidate)
        candidate=copy.deepcopy(config);candidate['roles']['Novel Role']['operations']=['send']
        with self.assertRaises(ValueError):general_builder.validate_config(candidate)
        self.assertTrue(general_builder.catalog_rows('Schnorr'))
        self.assertIn('unsupported',general_builder.catalog_rows('UDP')[0][-1])
        candidate=copy.deepcopy(config);candidate['hash']='sha1'
        self.assertIs(general_builder.validate_config(candidate),candidate)

    def test_schnorr_generated_signature(self):
        config={'title':'Generic signed records','fields':[{'name':'code','type':'text','required':True,'encrypted':False,'searchable':False}],
                'roles':{'Novel Signer':{'operations':['submit','verify'],'auth':False,'access':'all','view_fields':[],'decrypt_fields':[]}},
                'encryption':'none','aes_bits':128,'hash':'sha256','hmac_hash':'sha256','signature':'schnorr',
                'rsa_bits':2048,'aggregate_field':None,'paillier_bits':1024,'key_wrapping':False,
                'elgamal_bits':512,'schnorr_bits':1024,'shamir':None,'freshness_seconds':0,
                'textbook_rsa':False,'tcp_port':None,'architecture':'standalone','tcp_host':'127.0.0.1'}
        with tempfile.TemporaryDirectory() as d:
            path,_=general_builder.generate(config,Path(d)/'signed.py')
            spec=importlib.util.spec_from_file_location('signed',path)
            m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
            app=m.Application(Path(d)/'runtime')
            rid=app.submit('Novel Signer',{'code':'A'})
            self.assertTrue(app.verify('Novel Signer',rid))
            self.assertTrue(m.Application(Path(d)/'runtime').verify('Novel Signer',rid))
            row=copy.deepcopy(app.records()[0]);row['signature']['s']=str((int(row['signature']['s'])+1)%int(app.keys['schnorr']['q']))
            self.assertFalse(app.verify_signature(row))

    def test_separate_client_server_programs(self):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        config={'title':'Generic transfer','fields':[{'name':'payload','type':'text','required':True,'encrypted':False,'searchable':False}],
                'roles':{'Client Role':{'operations':['submit','send'],'auth':False,'access':'all','view_fields':[],'decrypt_fields':[]},
                         'Server Role':{'operations':['serve'],'auth':False,'access':'all','view_fields':[],'decrypt_fields':[]}},
                'encryption':'none','aes_bits':128,'hash':'sha256','hmac_hash':'sha256','signature':'none',
                'rsa_bits':2048,'aggregate_field':None,'paillier_bits':1024,'key_wrapping':False,
                'elgamal_bits':512,'schnorr_bits':2048,'shamir':None,'freshness_seconds':0,
                'textbook_rsa':False,'tcp_port':port,'architecture':'tcp_client_server','tcp_host':'127.0.0.1'}
        with tempfile.TemporaryDirectory() as d:
            path,report=general_builder.generate(config,Path(d)/'shared.py')
            server=path.with_name('shared_server.py');client=path.with_name('shared_client.py')
            self.assertTrue(server.exists() and client.exists())
            process=subprocess.Popen([sys.executable,'-B','-u',str(server)],cwd=d,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                for _ in range(50):
                    if process.poll() is not None:self.fail('Server exited before client connection')
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.2):break
                    except OSError:time.sleep(.1)
                else:self.fail('Server did not listen')
                result=subprocess.run([sys.executable,'-B',str(client)],input='hello\n',capture_output=True,text=True,timeout=10,cwd=d)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertIn("'ok': True",result.stdout)
                spec=importlib.util.spec_from_file_location('shared',path)
                module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
                self.assertEqual(len(module.Application(Path(d)/'demo_data'/'shared').records()),1)
                self.assertIn('start server first',report.read_text(encoding='utf-8'))
            finally:
                process.terminate();process.communicate(timeout=5)

if __name__=='__main__':unittest.main()
