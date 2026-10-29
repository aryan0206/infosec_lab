"""Guided project-local setup. Installation occurs only after an explicit Y response."""
import os
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent
VENV=ROOT/'.venv'
VENV_PY=VENV/'Scripts'/'python.exe' if os.name=='nt' else VENV/'bin'/'python'

def call(args,timeout=180):
    try:return subprocess.run(args,cwd=ROOT,timeout=timeout).returncode==0
    except (OSError,subprocess.TimeoutExpired) as exc:print('Command failed:',exc);return False

def main():
    print('SETUP: current Python',sys.version.split()[0],sys.executable)
    if not (3,10)<=sys.version_info[:2]<=(3,14):
        print('NOT READY: use CPython 3.10-3.14; 3.12 is preferred. Install a permitted user-local Python first.');return 1
    print('1 Full cryptographic builder (installs cryptography in .venv)')
    print('2 Standard-library-only Custom builds (no package installation)')
    print('0 Cancel')
    choice=input('Setup choice: ').strip()
    if choice=='0':return 0
    if choice not in ('1','2'):print('Invalid choice.');return 1
    wheelhouse=ROOT/'wheelhouse'
    offline=False
    if choice=='1':
        print('1 Install from compatible local wheelhouse (offline)')
        print('2 Install from PyPI (internet needed)')
        mode=input('Installation source: ').strip()
        if mode not in ('1','2'):print('Invalid choice.');return 1
        offline=mode=='1'
        if offline and not list(wheelhouse.glob('*.whl')):
            print('No wheel files in wheelhouse. Prepare them on a matching machine before the exam.');return 1
        if offline:
            try:
                manifest=json.loads((wheelhouse/'MANIFEST.json').read_text(encoding='utf-8'))
                target={'AMD64':'win_amd64','ARM64':'win_arm64','x86':'win32'}.get(platform.machine(),None)
                if manifest['target_platform']!=target or manifest['target_python']!=f'{sys.version_info.major}.{sys.version_info.minor}':
                    raise ValueError('Wheelhouse OS/architecture/Python target does not match this interpreter')
                for entry in manifest['wheels']:
                    wheel=wheelhouse/entry['file']
                    if not wheel.is_file() or hashlib.sha256(wheel.read_bytes()).hexdigest()!=entry['sha256']:
                        raise ValueError('Missing or changed wheel: '+entry['file'])
            except (OSError,ValueError,KeyError,TypeError) as exc:
                print('Offline wheelhouse check failed:',exc);return 1
    print('Target virtual environment:',VENV)
    if choice=='1':print('Packages will be installed ONLY into that environment.')
    if input('Proceed? Type Y to confirm: ').strip().lower()!='y':print('Cancelled; no installation performed.');return 0
    if not VENV_PY.is_file():
        if not call([sys.executable,'-m','venv',str(VENV)],timeout=90):
            print('Could not create .venv. Use a full CPython installation with venv and a writable folder.');return 1
    if not VENV_PY.is_file():print('Virtual environment Python is missing.');return 1
    if choice=='1':
        if not call([str(VENV_PY),'-m','pip','--version'],timeout=15):
            print('pip is missing inside .venv. Use a full Python installation with pip; no system packages were changed.');return 1
        args=[str(VENV_PY),'-m','pip','install']
        if offline:args+=['--no-index','--find-links',str(wheelhouse),'--only-binary=:all:']
        else:args+=['--only-binary=:all:']
        args+=['-r',str(ROOT/'requirements.txt')]
        print('Installing in project .venv only...')
        if not call(args):
            print('Installation failed. If offline, verify wheel OS, CPU, Python ABI and all transitive wheels. If online, check internet access.');return 1
    if not call([str(VENV_PY),'-B',str(ROOT/'exam_readiness.py')],timeout=90):
        print('Readiness failed. Read the issue and next action above.');return 1
    print('SETUP COMPLETE. Double-click START_TOOLKIT.bat and choose builder option 3.')
    return 0

if __name__=='__main__':raise SystemExit(main())
