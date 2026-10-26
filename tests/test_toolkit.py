import importlib.util
import json
import sys
import tempfile
import unittest
import subprocess
import shutil
import os
import socket
from html.parser import HTMLParser
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import core
def load(name):
    path=ROOT/'10_integrated_scenarios'/f'{name}.py'
    spec=importlib.util.spec_from_file_location(name,path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
patient_module=load('patient_records');PatientApp=patient_module.PatientApp
grant_module=load('grant_portal');GrantApp=grant_module.GrantApp
voting_module=load('e_voting_demo');VotingApp=voting_module.VotingApp

class CoreTests(unittest.TestCase):
    def test_rsa_product(self):
        n,e,d=core.rsa_textbook_parameters(5,11,3)
        exact=core.rsa_product(2,3,n,e,d)
        self.assertTrue(exact['modular_verified'])
        self.assertTrue(exact['ordinary_verified'])
        wrapped=core.rsa_product(10,10,n,e,d)
        self.assertTrue(wrapped['modular_verified'])
        self.assertFalse(wrapped['ordinary_verified'])
        self.assertFalse(wrapped['verified'])
        self.assertEqual(wrapped['decrypted'],45)
        self.assertEqual(wrapped['ordinary_product'],100)
        with self.assertRaises(ValueError):core.rsa_textbook_parameters(4,11,3)
        with self.assertRaises(ValueError):core.rsa_product(0,3,n,e,d)
        with self.assertRaises(ValueError):core.rsa_product(n,3,n,e,d)
        with self.assertRaises(ValueError):core.rsa_product(2,3,n,e,2)
    def test_paillier(self):
        pub,priv=core.paillier_keypair();cs=[core.paillier_encrypt(v,pub) for v in (2,3,4)]
        self.assertEqual(core.paillier_decrypt(core.paillier_add(cs,pub),pub,priv),9)
        with self.assertRaises(ValueError):core.paillier_encrypt(-1,pub)
        with self.assertRaises(ValueError):core.paillier_add([0],pub)
    def test_aes_hash_signature(self):
        key=b'1'*24;blob=core.aes_encrypt(b'hello',key);self.assertEqual(core.aes_decrypt(blob,key),b'hello')
        blob['ciphertext']=core.b64(b'bad')
        with self.assertRaises(Exception):core.aes_decrypt(blob,key)
        self.assertNotEqual(core.sha256(b'a'),core.sha256(b'b'))
        signer=core.rsa_keypair();sig=core.rsa_sign(b'hello',signer)
        self.assertTrue(core.rsa_verify(b'hello',sig,signer.public_key()))
        self.assertFalse(core.rsa_verify(b'other',sig,signer.public_key()))
        cbc=core.cbc_encrypt(b'vote',b'2'*32);self.assertEqual(core.cbc_decrypt(cbc,b'2'*32),b'vote')

class PatientTests(unittest.TestCase):
    def test_bulk_dataset_import_is_validated_before_write(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'supplied.csv'
            header='Patient_id,Patient_name,Diagnosis,Blood_glucose,Treatment\n'
            source.write_text(header+'P1,Ada,Diabetes,110,Diet\nP1,Bea,Asthma,90,Inhaler\n',encoding='utf-8')
            app=PatientApp(Path(d)/'records')
            with self.assertRaisesRegex(ValueError,'Duplicate patient ID'):app.load_dataset(source)
            self.assertFalse(app.plain.exists())
            source.write_text(header+'P1,Ada,Diabetes,110,Diet\nP2,Bea,Asthma,90,Inhaler\n',encoding='utf-8')
            self.assertEqual(app.load_dataset(source),2)
            self.assertEqual(app.records()[1]['Blood_glucose'],90)
            original=app.plain.read_bytes()
            with self.assertRaisesRegex(ValueError,'already exists'):app.load_dataset(source)
            self.assertEqual(app.plain.read_bytes(),original)
            app.encrypt_dataset();app.sign_dataset();self.assertTrue(PatientApp(app.dir).verify())
            malformed=Path(d)/'bad.json'
            malformed.write_text('[{"Patient_id":"P3"}]',encoding='utf-8')
            with tempfile.TemporaryDirectory() as fresh:
                target=PatientApp(fresh)
                with self.assertRaisesRegex(ValueError,'five exact fields'):target.load_dataset(malformed)
                self.assertFalse(target.plain.exists())
    def test_flow_restart_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            app=PatientApp(d);r={'Patient_id':'P1','Patient_name':'Ada','Diagnosis':'Diabetes','Blood_glucose':110,'Treatment':'Diet'}
            app.add(r)
            with self.assertRaises(ValueError):app.add(r)
            with self.assertRaisesRegex(ValueError,'Verification failed'):
                app.search('diab')
            self.assertEqual(app.aggregate()['decrypted_sum'],110)
            app.encrypt_dataset();app.sign_dataset();self.assertTrue(app.verify())
            self.assertEqual(app.search('diab'),[r])
            self.assertEqual(app.verified_record('P1'),r)
            again=PatientApp(d);self.assertEqual(again.verified_record('P1'),r)
            original=json.loads(again.encrypted.read_text())
            data=json.loads(json.dumps(original));data['records'][0]['aes']['ciphertext']='AAAA';again.encrypted.write_text(json.dumps(data))
            self.assertFalse(again.verify())
            with self.assertRaises(ValueError):again.verified_record('P1')
            with self.assertRaisesRegex(ValueError,'search blocked'):again.search('diab')
            data=json.loads(json.dumps(original));data['signature']='AAAA';again.encrypted.write_text(json.dumps(data))
            self.assertFalse(again.verify())
    def test_diagnosis_search_multiple_none_malformed_and_tampered(self):
        with tempfile.TemporaryDirectory() as d:
            app=PatientApp(d)
            first={'Patient_id':'P1','Patient_name':'Ada','Diagnosis':'Diabetes','Blood_glucose':110,'Treatment':'Diet'}
            second={'Patient_id':'P2','Patient_name':'Bea','Diagnosis':'diabetes type 2','Blood_glucose':95,'Treatment':'Medicine'}
            third={'Patient_id':'P3','Patient_name':'Cal','Diagnosis':'Asthma','Blood_glucose':80,'Treatment':'Inhaler'}
            for record in (first,second,third):app.add(record)
            app.encrypt_dataset();app.sign_dataset()
            self.assertEqual(app.search('DIAB'),[first,second])
            self.assertEqual(app.search('unknown'),[])
            encrypted=app.encrypted.read_text(encoding='utf-8')
            data=json.loads(encrypted);data['records'][0]['aes']['ciphertext']='AAAA'
            app.encrypted.write_text(json.dumps(data),encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'search blocked'):app.search('diab')
            app.encrypted.write_text('{bad',encoding='utf-8')
            with self.assertRaises(ValueError):app.search('diab')
            app.encrypted.write_text(json.dumps({'records':'not a list','signature':'AAAA'}),encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'search blocked'):app.search('diab')
            app.encrypted.write_text(encrypted,encoding='utf-8')
            app.plain.write_text('{bad',encoding='utf-8')
            with self.assertRaises(ValueError):app.search('diab')
    def test_empty_missing_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            app=PatientApp(d)
            with self.assertRaises(ValueError):app.aggregate()
            with self.assertRaises(ValueError):app.hash_record('x')
            app.plain.write_text('{bad')
            with self.assertRaises(ValueError):app.records()
            app.plain.write_text('[]')
            app.encrypted.write_text('{bad')
            with self.assertRaises(ValueError):app.verify()

class GrantTests(unittest.TestCase):
    def test_paillier_range_and_bounded_aggregate(self):
        with tempfile.TemporaryDirectory() as d:
            app=GrantApp(d);cap=grant_module.MAX_GRANT_AMOUNT;n=app.pub['n']
            self.assertEqual(grant_module.checked_total_capacity(2,2*cap+1),2*cap)
            with self.assertRaisesRegex(ValueError,'may wrap'):
                grant_module.checked_total_capacity(2,2*cap)
            with self.assertRaises(ValueError):grant_module.checked_total_capacity(-1,n)
            self.assertEqual(core.paillier_decrypt(core.paillier_add([core.paillier_encrypt(n-1,app.pub)],app.pub),app.pub,app.priv),n-1)
            self.assertEqual(core.paillier_decrypt(core.paillier_add([core.paillier_encrypt(n-1,app.pub),core.paillier_encrypt(1,app.pub)],app.pub),app.pub,app.priv),0)
            app.submit('MAX','Largest supported',cap)
            app.submit('ZERO','Zero',0)
            self.assertEqual(app.aggregate(['MAX','ZERO'])['decrypted_final_total'],cap)
            for bad in (cap+1,-1):
                with self.assertRaises(ValueError):app.submit(f'BAD{bad}','Invalid',bad)
            with self.assertRaises(ValueError):app.aggregate(['MAX','missing'])
            with self.assertRaises(ValueError):app.aggregate(['MAX','MAX'])
            original=app.records()
            legacy=json.loads(json.dumps(original))
            legacy[0].pop('format_version')
            legacy[0]['aes_description']=core.aes_encrypt(b'Largest supported',app.aes)
            legacy[0]['paillier_amount']=str(core.paillier_encrypt(cap,app.pub))
            protected={k:legacy[0][k] for k in ('grant_id','aes_description','paillier_amount')}
            legacy[0]['md5']=core.md5(core.canonical(protected))
            legacy[0]['signature']=core.rsa_sign(legacy[0]['md5'].encode(),app.rsa)
            app.path.write_text(json.dumps(legacy),encoding='utf-8')
            self.assertTrue(app.verified(app.records()[0]))
            with self.assertRaisesRegex(ValueError,'predates the amount-bound policy'):
                app.aggregate(['MAX'])
            tampered=json.loads(json.dumps(original));tampered[0]['paillier_amount']='1'
            app.path.write_text(json.dumps(tampered),encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'Signature/hash failure'):
                app.aggregate(['MAX'])
    def test_flow_restart_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            app=GrantApp(d);app.submit('G1','Study',100);app.submit('G2','Lab',20)
            self.assertEqual(app.search('G1'),{'grant_id':'G1','verified':True})
            self.assertEqual(app.description_hex('G1'),b'Study'.hex())
            self.assertEqual(GrantApp(d).aggregate(['G1','G2'])['decrypted_final_total'],120)
            views=GrantApp(d).submitted_views()
            self.assertEqual([v['grant_id'] for v in views],['G1','G2'])
            self.assertTrue(all(v['verified'] for v in views))
            self.assertNotIn('Study',str(views))
            self.assertEqual(bytes.fromhex(views[0]['aes_ciphertext_hex']),core.decode_bytes(app.records()[0]['aes_description']['ciphertext'],2))
            self.assertEqual(bytes.fromhex(views[0]['signature_hex']),core.decode_bytes(app.records()[0]['signature'],2))
            with self.assertRaises(ValueError):app.aggregate(['G1','missing'])
            with self.assertRaises(ValueError):app.aggregate(['G1','G1'])
            original=app.records();rows=json.loads(json.dumps(original));rows[0]['aes_description']['ciphertext']='AAAA';app.path.write_text(json.dumps(rows))
            self.assertFalse(app.search('G1')['verified'])
            with self.assertRaises(ValueError):app.description_hex('G1')
            with self.assertRaises(ValueError):app.aggregate(['G1'])
            with tempfile.TemporaryDirectory() as malformed:
                broken=GrantApp(malformed);broken.path.write_text('{bad')
                with self.assertRaises(ValueError):broken.records()
            rows=json.loads(json.dumps(original));rows[0]['signature']='AAAA';app.path.write_text(json.dumps(rows))
            self.assertFalse(app.verified(app.records()[0]))

class VotingTests(unittest.TestCase):
    def test_period_search_tally_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            app=VotingApp(d);now=datetime.now(timezone.utc)
            app.setup((now-timedelta(days=1)).isoformat(),(now+timedelta(days=1)).isoformat(),2)
            with self.assertRaises(ValueError):app.cast('early',1,'North',(now-timedelta(days=2)).isoformat())
            app.cast('B1',1,'North');app.cast('B2',2,'South')
            self.assertEqual([r['ballot_id'] for r in app.search('north')],['B1'])
            with self.assertRaisesRegex(ValueError,'election closes'):
                app.tally('A','B')
            closed=VotingApp(d,clock=lambda:now+timedelta(days=2))
            self.assertEqual(closed.tally('A','B')['final_counts'],{'1':1,'2':1})
            with self.assertRaisesRegex(ValueError,'approvals'):
                closed.tally('A','wrong')
            rows=app.rows();rows[0]['encrypted_indicators'][0]='5';app.path.write_text(json.dumps(rows))
            self.assertFalse(app.verify(app.rows()[0]))
            with self.assertRaises(ValueError):closed.tally('A','B')
            app.path.write_text('{bad')
            with self.assertRaises(ValueError):app.rows()
    def test_missing_ballots_after_close(self):
        with tempfile.TemporaryDirectory() as d:
            now=datetime.now(timezone.utc)
            app=VotingApp(d,clock=lambda:now+timedelta(days=2))
            app.setup((now-timedelta(days=1)).isoformat(),(now+timedelta(days=1)).isoformat(),2)
            with self.assertRaisesRegex(ValueError,'No ballots'):
                app.tally('A','B')

class NavigationTests(unittest.TestCase):
    def test_manual_5381_additive_hash(self):
        path=ROOT/'05_hashing_integrity_networking'/'hash_demo.py'
        spec=importlib.util.spec_from_file_location('hash_demo',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.assertEqual(module.lab_hash(''),5381)
        self.assertEqual(module.lab_hash('abc'),193485963)
        self.assertTrue(0<=module.lab_hash('A'*100)<2**32)

    def test_socket_hash_tampering_detected(self):
        with socket.socket() as free:
            free.bind(('127.0.0.1',0));port=free.getsockname()[1]
        script=str(ROOT/'05_hashing_integrity_networking'/'socket_hash_demo.py')
        env={**os.environ,'IS_LAB_HASH_PORT':str(port)}
        server=subprocess.Popen([sys.executable,script,'server'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
        try:
            self.assertIn('Listening',server.stdout.readline())
            client=subprocess.run([sys.executable,script,'client','--tamper'],input='hello\nworld\n',text=True,capture_output=True,timeout=10,env=env)
            self.assertEqual(client.returncode,0,client.stderr)
            self.assertIn('Tampering demo: one byte changed',client.stdout)
            self.assertIn('Match: False',client.stdout)
            self.assertEqual(server.wait(timeout=10),0)
        finally:
            if server.poll() is None:server.terminate();server.wait(timeout=5)
            server.stdout.close();server.stderr.close()
    def test_socket_hash_local_roundtrip(self):
        with socket.socket() as free:
            free.bind(('127.0.0.1',0));port=free.getsockname()[1]
        script=str(ROOT/'05_hashing_integrity_networking'/'socket_hash_demo.py')
        env={**os.environ,'IS_LAB_HASH_PORT':str(port)}
        server=subprocess.Popen([sys.executable,script,'server'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
        try:
            self.assertIn('Listening',server.stdout.readline())
            client=subprocess.run([sys.executable,script,'client'],input='hello\nworld\n',text=True,capture_output=True,timeout=10,env=env)
            self.assertEqual(client.returncode,0,client.stderr)
            self.assertIn('Match: True',client.stdout)
            self.assertEqual(server.wait(timeout=10),0)
        finally:
            if server.poll() is None:server.terminate();server.wait(timeout=5)
            server.stdout.close();server.stderr.close()
    def test_grant_role_menu_rejects_wrong_action(self):
        with tempfile.TemporaryDirectory() as d, patch('builtins.input',side_effect=['1','3','0','0']), patch('builtins.print') as output:
            grant_module.main(d)
            self.assertTrue(any('Invalid option for role.' in str(call) for call in output.call_args_list))
    def test_grant_researcher_menu_views_prior_submission(self):
        with tempfile.TemporaryDirectory() as d:
            GrantApp(d).submit('G1','Private description',25)
            with patch('builtins.input',side_effect=['1','2','0','0']), patch('builtins.print') as output:
                grant_module.main(d)
            displayed='\n'.join(str(call) for call in output.call_args_list)
            self.assertIn('G1',displayed)
            self.assertIn('AES encrypted description (hex):',displayed)
            self.assertIn('RSA signature (hex):',displayed)
            self.assertNotIn('Private description',displayed)
    def test_patient_invalid_menu_choice(self):
        with tempfile.TemporaryDirectory() as d, patch('builtins.input',side_effect=['x','9']), patch('builtins.print') as output:
            patient_module.main(d)
            self.assertTrue(any('Invalid option.' in str(call) for call in output.call_args_list))
    def test_html_links_exist(self):
        class Links(HTMLParser):
            def __init__(self):super().__init__();self.links=[]
            def handle_starttag(self,tag,attrs):
                if tag=='a':self.links.extend(v for k,v in attrs if k=='href')
        parser=Links();parser.feed((ROOT/'index.html').read_text(encoding='utf-8'))
        self.assertGreater(len(parser.links),20)
        for link in parser.links:self.assertTrue((ROOT/link.split('#')[0]).exists(),link)
    def test_standalone_rsa_menu(self):
        run=subprocess.run([sys.executable,str(ROOT/'standalone_submissions'/'rsa_product.py')],input='1\n1\n5\n11\n3\n2\n2\n3\n0\n',text=True,capture_output=True,timeout=15)
        self.assertEqual(run.returncode,0,run.stderr);self.assertIn('Ordinary product verified: 6',run.stdout)
        supplied=subprocess.run([sys.executable,str(ROOT/'standalone_submissions'/'rsa_product.py')],input='1\n2\n55\n3\n27\n2\n2\n3\n0\n',text=True,capture_output=True,timeout=15)
        self.assertEqual(supplied.returncode,0,supplied.stderr);self.assertIn('Ordinary product verified: 6',supplied.stdout)
        wrapped=subprocess.run([sys.executable,str(ROOT/'standalone_submissions'/'rsa_product.py')],input='1\n1\n5\n11\n3\n2\n10\n10\n0\n',text=True,capture_output=True,timeout=15)
        self.assertEqual(wrapped.returncode,0,wrapped.stderr)
        self.assertIn('Modular homomorphic equality verified',wrapped.stdout)
        self.assertIn('Ordinary product not verified',wrapped.stdout)
        self.assertNotIn('Ordinary product verified:',wrapped.stdout)
        invalid=subprocess.run([sys.executable,str(ROOT/'standalone_submissions'/'rsa_product.py')],input='1\n2\n55\n3\n2\n0\n',text=True,capture_output=True,timeout=15)
        self.assertEqual(invalid.returncode,0,invalid.stderr)
        self.assertIn('Parameters fail sample round trips',invalid.stdout)
    def test_rsa_submission_runs_alone(self):
        with tempfile.TemporaryDirectory() as d:
            isolated=Path(d)/'rsa_product.py'
            shutil.copy2(ROOT/'standalone_submissions'/'rsa_product.py',isolated)
            run=subprocess.run([sys.executable,'-B',str(isolated)],cwd=d,
                               input='1\n1\n5\n11\n3\n2\n2\n3\n0\n',
                               text=True,capture_output=True,timeout=15)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertIn('Ordinary product verified: 6',run.stdout)
            self.assertEqual(sorted(p.name for p in Path(d).iterdir()),['rsa_product.py'])
    def test_standalone_paillier_menu(self):
        run=subprocess.run([sys.executable,str(ROOT/'standalone_submissions'/'paillier_sum.py')],input='1\n2,3\n0\n',text=True,capture_output=True,timeout=25)
        self.assertEqual(run.returncode,0,run.stderr);self.assertIn('Final decrypted sum: 5',run.stdout)
    def test_router_and_lab_examples(self):
        import exam_router
        self.assertTrue(any('rsa_product' in path for path,_ in exam_router.route('multiply encrypted values using RSA')))
        self.assertTrue(any('elgamal_product' in path for path,_ in exam_router.route('ElGamal encrypted multiplication')))
        classical=ROOT/'01_basic_ciphers'/'classical.py'
        spec=importlib.util.spec_from_file_location('classical',classical);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        self.assertEqual(mod.affine(mod.affine('HELLO',5,8),5,8,True),'HELLO')
        self.assertEqual(mod.rail_fence(mod.rail_fence('HELLO',3),3,True),'HELLO')
        self.assertEqual(mod.autokey(mod.autokey('HELLO',7),7,True),'HELLO')
        self.assertEqual(mod.hill2(mod.hill2('HELP',(3,3,2,5)),(3,3,2,5),True),'HELP')
        self.assertEqual(mod.playfair(mod.playfair('HIDE', 'MONARCHY'),'MONARCHY',True),'HIDE')
        public,private=core.elgamal_keypair();digest=bytes.fromhex(core.sha512(b'ballot'));sig=core.elgamal_sign_digest(digest,public,private)
        self.assertTrue(core.elgamal_verify_digest(digest,sig,public))
        self.assertFalse(core.elgamal_verify_digest(bytes.fromhex(core.sha512(b'tampered')),sig,public))

if __name__=='__main__':unittest.main()
