"""Regression checks for configurable one-file builder and unfamiliar ledger scenario."""
import ast
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import master_builder as builder

class BuilderTests(unittest.TestCase):
    def generated(self,d,features=None):
        with patch.object(builder,'OUTPUT',Path(d)):
            path,report,selected=builder.build('2',features or builder.FULL)
        return path,report,selected

    def test_custom_selection_conflict_and_required(self):
        with patch('builtins.input',side_effect=['3','1,2,3,4']):
            self.assertIsNone(builder.select_features('6'))
        with patch('builtins.input',side_effect=['3','']):
            chosen=builder.select_features('2')
        self.assertTrue(builder.FAMILIES['2'][2] <= chosen)
        self.assertNotIn('approval',chosen)

    def test_new_output_no_overwrite_and_standalone(self):
        with tempfile.TemporaryDirectory() as d:
            p1,r1,_=self.generated(d)
            p2,r2,_=self.generated(d)
            self.assertNotEqual(p1,p2)
            self.assertTrue(p1.exists() and p2.exists() and r1.exists() and r2.exists())
            tree=ast.parse(p1.read_text(encoding='utf-8'))
            self.assertFalse(any(isinstance(n,ast.ImportFrom) and n.module in {'core','store','master_builder'} for n in ast.walk(tree)))
            with patch.object(builder,'OUTPUT',Path(d)):
                self.assertIn('functional self-test PASSED',builder.validate(p1))

    def test_missing_dependency_blocks_generation(self):
        with tempfile.TemporaryDirectory() as d, patch.object(builder,'OUTPUT',Path(d)),patch.object(builder,'inspect_environment',return_value=['cryptography is missing']):
            with self.assertRaisesRegex(ValueError,'cryptography is missing'):builder.build('2',builder.FULL)
            self.assertEqual(list(Path(d).iterdir()),[])

    def test_hash_only_build_needs_no_cryptography(self):
        with tempfile.TemporaryDirectory() as d,patch.object(builder,'OUTPUT',Path(d)),patch.object(builder,'inspect_environment',return_value=[]) as check:
            path,report,features=builder.build('6',{'sha256','search','audit'})
            check.assert_called_once_with(require_cryptography=False)
            source=path.read_text(encoding='utf-8')
            self.assertNotIn('import cryptography',source)
            self.assertIn('standard library only',report.read_text(encoding='utf-8'))
            self.assertIn('functional self-test PASSED',builder.validate(path))

    def test_md5_grant_custom_profile(self):
        with tempfile.TemporaryDirectory() as d, patch.object(builder,'OUTPUT',Path(d)):
            selected=set(builder.FAMILIES['2'][2])|{'md5','audit'}
            path,report,actual=builder.build('2',selected)
            self.assertIn('md5',actual)
            self.assertNotIn('sha256',actual)
            self.assertIn('functional self-test PASSED',builder.validate(path))

    def test_local_aes128_sha512_and_stdlib_sha512(self):
        with tempfile.TemporaryDirectory() as d,patch.object(builder,'OUTPUT',Path(d)):
            path,_,features=builder.build('1',{'aes','researcher_sig','search','sha512'},{'aes_bits':128})
            self.assertIn('sha512',features)
            self.assertNotIn('sha256',features)
            self.assertIn('functional self-test PASSED',builder.validate(path))
            spec=importlib.util.spec_from_file_location('local_variant',path)
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            app=module.Ledger(Path(d)/'variant_data')
            record=app.submit('A','P','C','note',3)
            self.assertEqual(len(app.aes),16)
            self.assertEqual(len(record['record_hash']),128)
            self.assertTrue(app.verify_record(record))
            plain,_,_=builder.build('6',{'sha512','search','audit'})
            self.assertNotIn('cryptography',plain.read_text(encoding='utf-8'))
            self.assertIn('functional self-test PASSED',builder.validate(plain))

    def test_unfamiliar_research_ledger_restart_aggregate_and_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            path,report,selected=self.generated(d)
            self.assertTrue({'aes','paillier','sha256','researcher_sig','reviewer_sig','approval','audit','aggregate'} <= selected)
            spec=importlib.util.spec_from_file_location('generated_ledger',path)
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            data=Path(d)/'runtime'
            app=module.Ledger(data)
            module.demo(app)
            self.assertEqual(app.aggregate(['E1','E2'],'P1',300)['final_total'],200)
            with self.assertRaisesRegex(ValueError,'approval'):app.aggregate(['E1','E3'],'P1',300)
            with self.assertRaisesRegex(ValueError,'Mixed-project'):app.aggregate(['E1','E2'],'P2',300)
            with self.assertRaisesRegex(ValueError,'Duplicate'):app.submit('E1','P1','Lab','Again',1)
            self.assertTrue(app.search('E1')['verified'])
            self.assertEqual(app.description_hex('E1'),'Demo expense E1'.encode().hex())
            self.assertIsNone(app.prior_submissions()[0]['amount_plaintext'])
            self.assertTrue(app.prior_submissions()[0]['amount_ciphertext_hex'].startswith('0x'))
            again=module.Ledger(data)
            self.assertEqual(again.aggregate(['E1','E2'],'P1',300)['final_total'],200)
            self.assertTrue(again.aggregate(['E1','E2'],'P1',100)['exceeds_budget'])
            self.assertNotEqual((data/'researcher_private.pem').read_bytes(),(data/'reviewer_private.pem').read_bytes())
            with patch.object(module,'paillier_decrypt',wraps=module.paillier_decrypt) as decrypt:
                again.aggregate(['E1','E2'],'P1',300)
                self.assertEqual(decrypt.call_count,1)
            with self.assertRaisesRegex(ValueError,'not found'):again.search('MISSING')
            with self.assertRaisesRegex(ValueError,'distinct'):again.aggregate(['E1','E1'],'P1',300)
            again.decide('E3','approved','Explicit new approval after review')
            self.assertEqual(again.aggregate(['E1','E3'],'P1',300)['final_total'],170)
            events=json.loads((data/'events.json').read_text(encoding='utf-8'))
            original_events=json.loads(json.dumps(events))
            decision=next(e for e in events if e['type']=='decision')
            decision['payload']['reviewer_signature']='AAAA'
            previous='0'*64
            for event in events:
                event['prev_hash']=previous
                event['event_hash']=module.sha256(module.canonical({k:event[k] for k in ('type','payload','prev_hash')}))
                previous=event['event_hash']
            (data/'events.json').write_text(json.dumps(events),encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'approval'):again.aggregate(['E1','E2'],'P1',300)
            events=json.loads(json.dumps(original_events))
            original=events[0]['payload']
            protected={k:original[k] for k in ('expense_id','project_id','category','description','amount')}
            self.assertEqual(original['record_hash'],module.sha256(module.canonical(protected)))
            events[0]['payload']['project_id']='P9'
            (data/'events.json').write_text(json.dumps(events),encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'hash chain'):again.aggregate(['E1','E2'],'P1',300)
            (data/'events.json').write_text('{bad',encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'Malformed stored file'):again.records()

    def test_menu_without_question_and_batch_outside_cwd(self):
        python=sys.executable
        env={**os.environ,'IS_LAB_PYTHON':python,'PYTHONDONTWRITEBYTECODE':'1'}
        if os.name=='nt':
            result=subprocess.run(['cmd','/c',str(ROOT/'START_TOOLKIT.bat')],cwd=ROOT.parent,
                                  input='0\n\n',text=True,capture_output=True,timeout=20,env=env)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('EXAM PC TOOLKIT',result.stdout)
            self.assertNotIn('Paste/type the exam question',result.stdout)
        result=subprocess.run([python,'-B',str(ROOT/'master_builder.py')],cwd=ROOT.parent,
                              input='bad\n6\n0\n0\n',text=True,capture_output=True,timeout=20,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('Invalid choice',result.stdout)
        self.assertNotIn('Paste/type the exam question',result.stdout)

if __name__=='__main__':unittest.main()
