"""Package safe source files, then extract and smoke-test the ZIP outside this project."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parent
ZIP=ROOT.parent/'IS_Lab_Endsem_Portable.zip'
EXCLUDED={'exam_output','.venv','__pycache__','demo_data','.pytest_cache','.mypy_cache','.git','wheelhouse'}
EXTENSIONS={'.py','.bat','.md','.txt','.html','.js'}

def files(include_wheelhouse=False):
    result=[]
    for path in ROOT.rglob('*'):
        if not path.is_file():continue
        relative=path.relative_to(ROOT)
        if any(part in EXCLUDED for part in relative.parts):continue
        if path.name in {'ZIP_VERIFICATION.txt','PRACTICE_PROGRESS.md'}:continue
        if path.suffix.lower() not in EXTENSIONS and path.name!='requirements.txt':continue
        if any(word in path.name.lower() for word in ('private.pem','secret','password')):continue
        result.append(path)
    if include_wheelhouse:
        manifest=ROOT/'wheelhouse'/'MANIFEST.json'
        data=json.loads(manifest.read_text(encoding='utf-8'))
        wheels=[]
        for entry in data['wheels']:
            path=ROOT/'wheelhouse'/entry['file']
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=entry['sha256']:
                raise ValueError('Wheelhouse manifest check failed: '+entry['file'])
            wheels.append(path)
        if not wheels:raise ValueError('Wheelhouse manifest lists no wheels')
        result.extend([manifest]+wheels)
    return sorted(result)

def check_extract(zip_path,include_wheelhouse=False):
    with tempfile.TemporaryDirectory(prefix='exam_zip_check_') as directory:
        extracted=Path(directory)/'extracted copy with spaces';extracted.mkdir()
        with zipfile.ZipFile(zip_path) as archive:
            bad=archive.testzip()
            if bad:raise ValueError('Damaged ZIP entry: '+bad)
            archive.extractall(extracted)
        required=['EXAM_QUICK_START.txt','START_TOOLKIT.bat','master_builder.py','components/ledger_scenario.py',
                  'components/stdlib_ledger.py','exam_readiness.py','requirements.txt','tests/test_master_builder.py']
        missing=[p for p in required if not (extracted/p).is_file()]
        if missing:raise ValueError('ZIP missing: '+', '.join(missing))
        env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'}
        tests=[([sys.executable,'-B',str(extracted/'components'/'stdlib_ledger.py'),'--self-test'],'SELF-TEST PASSED'),
               ([sys.executable,'-B',str(extracted/'components'/'ledger_scenario.py'),'--self-test'],'SELF-TEST PASSED'),
               ([sys.executable,'-B','-c',"import master_builder as b; p,r,_=b.build('6',{'sha256','search','audit'}); print(b.validate(p))"],'functional self-test PASSED'),
               ([sys.executable,'-B','-c',"import master_builder as b; p,r,_=b.build('2',b.FULL); print(b.validate(p))"],'functional self-test PASSED')]
        if os.name=='nt':tests.append((['cmd','/c',str(extracted/'START_TOOLKIT.bat')],'IS LAB ENDSEM - EXAM PC TOOLKIT'))
        for command,expected in tests:
            run=subprocess.run(command,cwd=extracted,input='0\n' if command[0]=='cmd' else None,
                               capture_output=True,text=True,timeout=90,env=env)
            if run.returncode or expected not in run.stdout:
                raise ValueError('Extracted-copy test failed: '+str(command)+'\n'+run.stdout[-500:]+'\n'+run.stderr[-500:])
        if include_wheelhouse:
            manifest=json.loads((extracted/'wheelhouse'/'MANIFEST.json').read_text(encoding='utf-8'))
            current={'AMD64':'win_amd64','ARM64':'win_arm64','x86':'win32'}.get(__import__('platform').machine())
            if manifest['target_platform']==current and manifest['target_python']==f'{sys.version_info.major}.{sys.version_info.minor}':
                venv=extracted/'offline_test_venv'
                subprocess.run([sys.executable,'-m','venv',str(venv)],check=True,timeout=90)
                interpreter=venv/'Scripts'/'python.exe' if os.name=='nt' else venv/'bin'/'python'
                install=subprocess.run([str(interpreter),'-m','pip','install','--no-index','--find-links',str(extracted/'wheelhouse'),'-r',str(extracted/'requirements.txt')],
                                       cwd=extracted,capture_output=True,text=True,timeout=180)
                if install.returncode:raise ValueError('Offline install failed: '+install.stderr[-500:])
                smoke=subprocess.run([str(interpreter),'-B',str(extracted/'components'/'ledger_scenario.py'),'--self-test'],
                                     cwd=extracted,capture_output=True,text=True,timeout=60)
                if smoke.returncode:raise ValueError('Offline cryptographic smoke test failed: '+smoke.stderr[-500:])
            else:print('Wheelhouse target differs from this PC; offline install was NOT tested here.')
    return True

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--include-wheelhouse',action='store_true',help='include a verified, target-specific wheelhouse')
    args=parser.parse_args()
    selected=files(args.include_wheelhouse)
    with zipfile.ZipFile(ZIP,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for path in selected:archive.write(path,path.relative_to(ROOT).as_posix())
    print('ZIP:',ZIP,'files:',len(selected))
    check_extract(ZIP,args.include_wheelhouse)
    report=ROOT/'ZIP_VERIFICATION.txt'
    report.write_text(f'ZIP: {ZIP.name}\nFiles: {len(selected)}\nExtracted-copy smoke: PASSED\n'
                      f'Wheelhouse included: {args.include_wheelhouse}\nHost Python: {sys.version.split()[0]}\n',encoding='utf-8')
    print('EXTRACTED-COPY CHECK PASSED. Report:',report)

if __name__=='__main__':main()
