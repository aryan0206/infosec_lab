"""Terminal navigation checks without launching an exam program in the test runner."""
import contextlib
import io
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import check_setup
import exam_router

class NavigationReadinessTests(unittest.TestCase):
    def test_question_ranking_and_unsupported_wording(self):
        self.assertEqual(exam_router.find_submissions('patient diagnosis glucose RSA sign')[0]['name'],'Patient records')
        self.assertEqual(exam_router.find_submissions('grant description AES-192 Paillier total')[0]['name'],'Grant expense portal')
        self.assertEqual(exam_router.find_submissions('voter ballot deadline threshold')[0]['name'],'E-voting educational demonstration')
        self.assertEqual(exam_router.find_submissions('multiply RSA encrypted boxes cost')[0]['name'],'RSA encrypted product')
        self.assertEqual(exam_router.find_submissions('multiply encrypted values using RSA')[0]['name'],'RSA encrypted product')
        self.assertEqual(exam_router.find_submissions('sum Paillier encrypted integers')[0]['name'],'Paillier integer sum')
        self.assertEqual(exam_router.find_submissions('ElGamal encrypted multiplication')[0]['name'],'ElGamal encrypted product')
        self.assertEqual(exam_router.find_submissions('Schnorr signature only'),[])

    def test_preview_has_command_inputs_coverage_and_limitations(self):
        for item in exam_router.SUBMISSIONS:
            output=io.StringIO()
            with contextlib.redirect_stdout(output):exam_router.preview(item,'trusted timestamp threshold')
            shown=output.getvalue()
            self.assertIn(str(ROOT/item['path']),shown)
            self.assertIn(exam_router.command_for(item),shown)
            self.assertIn('Required inputs:',shown)
            self.assertIn('Limitations:',shown)
            self.assertIn('UNSUPPORTED extra:',shown)
            self.assertIn('Requirement coverage',shown)
        self.assertIn('9 Exit',exam_router.SUBMISSIONS[2]['coverage'][1][1])

    def test_preflight_missing_dependency_and_stale_export(self):
        rsa=exam_router.SUBMISSIONS[0]
        grant=exam_router.SUBMISSIONS[3]
        with patch('exam_router.inspect_environment',return_value=['cryptography missing']) as check:
            self.assertEqual(exam_router.preflight(grant),['cryptography missing'])
            check.assert_called_with(require_cryptography=True)
        with patch('exam_router.inspect_environment',return_value=[]),patch('exam_router.subprocess.run') as run:
            run.return_value.returncode=1
            run.return_value.stdout='stale'
            run.return_value.stderr=''
            self.assertTrue(any('stale' in error for error in exam_router.preflight(rsa)))
            self.assertIn('--check',run.call_args.args[0])
        with patch('exam_router.inspect_environment',return_value=[]),patch('exam_router.ROOT',Path('C:/missing-toolkit')):
            self.assertTrue(any('Missing submission' in error for error in exam_router.preflight(rsa)))

    def test_confirmation_and_invalid_choices(self):
        item=exam_router.SUBMISSIONS[0]
        with patch('exam_router.preflight',return_value=[]),patch('builtins.input',return_value='n'),patch('exam_router.subprocess.run') as run,contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(exam_router.offer_launch(item))
            run.assert_not_called()
        with patch('exam_router.preflight',return_value=[]),patch('builtins.input',return_value='y'),patch('exam_router.subprocess.run') as run,contextlib.redirect_stdout(io.StringIO()):
            run.return_value.returncode=0
            self.assertTrue(exam_router.offer_launch(item))
            self.assertEqual(run.call_args.args[0],[sys.executable,'-B',str(ROOT/item['path'])])
        with patch('builtins.input',side_effect=['bad','0']),patch('exam_router.offer_launch') as launch,contextlib.redirect_stdout(io.StringIO()) as output:
            exam_router.main()
            launch.assert_not_called()
            self.assertIn('Invalid choice',output.getvalue())

    def test_runtime_check_is_dependency_specific(self):
        self.assertEqual(check_setup.inspect_environment(False),[])
        with patch.dict(sys.modules,{'cryptography':None}):
            self.assertEqual(check_setup.inspect_environment(False),[])
            self.assertTrue(any('cryptography' in error for error in check_setup.inspect_environment(True)))

    @unittest.skipUnless(os.name=='nt','Windows batch entry point')
    def test_batch_entrypoint_uses_selected_interpreter(self):
        environment={**os.environ,'IS_LAB_PYTHON':sys.executable,'PYTHONDONTWRITEBYTECODE':'1'}
        result=subprocess.run(['cmd','/c',str(ROOT/'START_TOOLKIT.bat')],cwd=ROOT,
                              input='0\n\n',text=True,capture_output=True,timeout=20,env=environment)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('Check examination PC readiness',result.stdout)
        self.assertIn('EXAM PC TOOLKIT',result.stdout)

    def test_new_copy_and_missing_warning(self):
        import ast
        import tempfile
        with tempfile.TemporaryDirectory() as d, patch('exam_router.OUTPUT',Path(d)):
            item=exam_router.SUBMISSIONS[0]
            target,checklist=exam_router.create_submission(item,'Multiply RSA encrypted boxes and cost with Schnorr signature')
            self.assertTrue(target.is_file())
            self.assertTrue(checklist.is_file())
            self.assertIn('Schnorr signatures are not supplied',checklist.read_text(encoding='utf-8'))
            tree=ast.parse(target.read_text(encoding='utf-8'))
            self.assertFalse(any(isinstance(node,ast.ImportFrom) and node.module in {'core','store'} for node in ast.walk(tree)))
            run=subprocess.run([sys.executable,'-B',str(target)],cwd=d,input='1\n1\n5\n11\n3\n2\n2\n3\n0\n',
                               text=True,capture_output=True,timeout=15)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertIn('Ordinary product verified: 6',run.stdout)

if __name__=='__main__':unittest.main()
