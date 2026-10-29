"""Environment failure cases and portable launcher behavior."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import exam_readiness as ready

def response(code=0,output=''):
    return SimpleNamespace(returncode=code,stdout=output,stderr='')

class ReadinessTests(unittest.TestCase):
    def test_multiple_interpreters_and_duplicate_paths(self):
        infos={'one':{'version':[3,9,9],'executable':'C:/old/python.exe','implementation':'CPython'},
               'two':{'version':[3,12,14],'executable':'C:/new/python.exe','implementation':'CPython'},
               'three':{'version':[3,12,14],'executable':'C:/new/python.exe','implementation':'CPython'}}
        with patch.object(ready,'probe',side_effect=lambda command:infos[command[0]]):
            found=ready.discovered([['one'],['two'],['three']])
        self.assertEqual(len(found),2)
        self.assertEqual(found[1]['version'][:2],[3,12])

    def test_missing_pip_and_dependency_are_limitations(self):
        info={'version':[3,12,14],'executable':'C:/python.exe','implementation':'CPython'}
        def fake_run(args,timeout=20):
            if 'pip' in args:return response(1)
            if 'cryptography' in ' '.join(args):return response(1)
            if '--self-test' in args:return response(0,'SELF-TEST PASSED')
            return response(0)
        with patch.object(ready,'probe',return_value=info),patch.object(ready,'run',side_effect=fake_run),patch.object(ready,'writable',return_value=True),patch.object(ready,'discovered',return_value=[]):
            result=ready.check('C:/python.exe',probe_venv=False)
        self.assertEqual(result['status'],'READY WITH LIMITATIONS')
        self.assertFalse(result['pip'])
        self.assertFalse(result['cryptography_compatible'])

    def test_unsupported_and_absent_python_not_ready(self):
        for info in ({'version':[3,9,18],'executable':'C:/old.exe','implementation':'CPython'},None):
            with self.subTest(info=info),patch.object(ready,'probe',return_value=info),patch.object(ready,'run',return_value=None),patch.object(ready,'writable',return_value=True),patch.object(ready,'discovered',return_value=[]):
                result=ready.check('C:/absent.exe',probe_venv=False)
                self.assertEqual(result['status'],'NOT READY')

    def test_incorrect_cryptography_version_is_reported(self):
        info={'version':[3,12,14],'executable':'C:/python.exe','implementation':'CPython'}
        def fake_run(args,timeout=20):
            if 'cryptography' in ' '.join(args):return response(0,'40.0.0\n')
            if '--self-test' in args:return response(0,'SELF-TEST PASSED')
            return response(0,'pip 26')
        with patch.object(ready,'probe',return_value=info),patch.object(ready,'run',side_effect=fake_run),patch.object(ready,'writable',return_value=True),patch.object(ready,'discovered',return_value=[]):
            result=ready.check('C:/python.exe',probe_venv=False)
        self.assertEqual(result['status'],'READY WITH LIMITATIONS')
        self.assertEqual(result['cryptography_version'],'40.0.0')
        self.assertFalse(result['cryptography_compatible'])

    @unittest.skipUnless(os.name=='nt','Windows BAT')
    def test_batch_without_python_stays_open_and_reports_next_action(self):
        with tempfile.TemporaryDirectory(prefix='No Python exam ') as d:
            bat=Path(d)/'START_TOOLKIT.bat';bat.write_bytes((ROOT/'START_TOOLKIT.bat').read_bytes())
            env={**os.environ,'PATH':str(Path(os.environ['SystemRoot'])/'System32'),
                 'USERPROFILE':d,'LOCALAPPDATA':d,'IS_LAB_PYTHON':str(Path(d)/'missing.exe')}
            result=subprocess.run(['cmd','/c',str(bat)],cwd=ROOT.parent,input='1\n0\n',
                                  text=True,capture_output=True,timeout=20,env=env)
            self.assertIn('NOT READY',result.stdout)
            self.assertIn('Python cannot be installed with pip',result.stdout)
            self.assertIn('Next action:',result.stdout)

if __name__=='__main__':unittest.main()
