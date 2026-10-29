"""Read-only checks except temporary write/venv probes; never installs packages."""
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parent
MIN_VERSION=(3,10);MAX_VERSION=(3,14)

def run(command,timeout=20):
    try:return subprocess.run(command,capture_output=True,text=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired):return None

def candidates(env=None):
    env=env or os.environ
    result=[]
    if env.get('IS_LAB_PYTHON'):result.append([env['IS_LAB_PYTHON']])
    venv=ROOT/'.venv'/'Scripts'/'python.exe'
    if venv.exists():result.append([str(venv)])
    for version in ('3.12','3.13','3.14','3.11','3.10'):
        result.append(['py',f'-{version}'])
    result.extend([['py','-3'],['python'],['python3']])
    local=Path(env.get('LOCALAPPDATA',''))/'Programs'/'Python'
    for version in ('312','313','314','311','310'):
        result.append([str(local/f'Python{version}'/'python.exe')])
    result.append([str(Path(env.get('USERPROFILE',''))/'.cache'/'codex-runtimes'/'codex-primary-runtime'/'dependencies'/'python'/'python.exe')])
    return result

def probe(command):
    script='import json,sys,platform;print(json.dumps({"version":list(sys.version_info[:3]),"executable":sys.executable,"implementation":platform.python_implementation(),"architecture":platform.machine()}))'
    outcome=run(command+['-c',script],timeout=8)
    if outcome is None or outcome.returncode:return None
    try:return json.loads(outcome.stdout.strip().splitlines()[-1])
    except (ValueError,IndexError):return None

def discovered(candidates_list=None):
    found=[];seen=set()
    for command in (candidates_list if candidates_list is not None else candidates()):
        info=probe(command)
        if info and info['executable'].casefold() not in seen:
            seen.add(info['executable'].casefold());found.append(info)
    return found

def writable(directory):
    try:
        directory.mkdir(parents=True,exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=directory,prefix='.write_probe_',delete=True):pass
        return True
    except OSError:return False

def check(interpreter=None,probe_venv=True):
    interpreter=interpreter or sys.executable
    issues=[];actions=[]
    selected=probe([interpreter])
    version=tuple(selected['version'][:2]) if selected else (0,0)
    implementation=selected['implementation'] if selected else 'not found'
    supported=implementation=='CPython' and MIN_VERSION<=version<=MAX_VERSION
    if not supported:
        issues.append('This interpreter is outside supported CPython 3.10-3.14.')
        actions.append('Select or install a permitted CPython 3.12 interpreter, then rerun readiness.')
    source_ok=all((ROOT/p).is_file() for p in ('master_builder.py','components/ledger_scenario.py','components/stdlib_ledger.py','components/network_record_scenario.py','requirements.txt'))
    if not source_ok:issues.append('Required toolkit source files are missing.');actions.append('Extract the complete ZIP again.')
    root_write=writable(ROOT);output_write=writable(ROOT/'exam_output')
    if not root_write or not output_write:
        issues.append('Toolkit or output folder is not writable.');actions.append('Extract the ZIP to a writable user folder, not Program Files or a read-only drive.')
    pip_result=run([interpreter,'-m','pip','--version'])
    pip_ok=bool(pip_result and pip_result.returncode==0)
    if not pip_ok:issues.append('pip is unavailable.');actions.append('Use a full Python installation with pip; package installation cannot proceed here.')
    venv_ok=None
    if probe_venv and root_write:
        with tempfile.TemporaryDirectory(dir=ROOT,prefix='.venv_probe_') as tmp:
            result=run([interpreter,'-m','venv','--without-pip',str(Path(tmp)/'probe')],timeout=40)
            venv_ok=bool(result and result.returncode==0 and (Path(tmp)/'probe'/'pyvenv.cfg').exists())
        if not venv_ok:issues.append('A local virtual environment could not be created.');actions.append('Use a full Python installation and a writable extracted folder.')
    cryptography_version=None;crypto_ok=False
    result=run([interpreter,'-c','import cryptography; from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print(cryptography.__version__)'])
    if result and result.returncode==0:
        cryptography_version=result.stdout.strip().splitlines()[-1]
        try:
            parts=tuple(int(x) for x in cryptography_version.split('.')[:2]);crypto_ok=(41,0)<=parts<(51,0)
        except ValueError:pass
    if not crypto_ok:issues.append('cryptography>=41,<51 is missing, incompatible, or not importable.');actions.append('Choose setup option 2 with internet or a compatible wheelhouse, or use a standard-library-only Custom build.')
    stdlib_smoke=False;crypto_smoke=None;network_smoke=None
    if supported and source_ok:
        result=run([interpreter,'-B',str(ROOT/'components'/'stdlib_ledger.py'),'--self-test'],timeout=30)
        stdlib_smoke=bool(result and result.returncode==0 and 'SELF-TEST PASSED' in result.stdout)
        if not stdlib_smoke:issues.append('Standard-library application smoke test failed.');actions.append('Re-extract the toolkit and rerun readiness.')
        if crypto_ok:
            result=run([interpreter,'-B',str(ROOT/'components'/'ledger_scenario.py'),'--self-test'],timeout=45)
            crypto_smoke=bool(result and result.returncode==0 and 'SELF-TEST PASSED' in result.stdout)
            if not crypto_smoke:issues.append('Cryptographic application smoke test failed.');actions.append('Repair the cryptography installation or use the standard-library-only profile.')
            result=run([interpreter,'-B',str(ROOT/'components'/'network_record_scenario.py'),'--self-test'],timeout=45)
            network_smoke=bool(result and result.returncode==0 and 'SELF-TEST PASSED' in result.stdout)
            if not network_smoke:issues.append('Networked-record smoke test failed.');actions.append('Check local loopback sockets and cryptography before using framed TCP.')
    generated=sorted((ROOT/'exam_output').glob('*.py')) if (ROOT/'exam_output').exists() else []
    syntax_result=None
    if generated:
        target=generated[-1]
        result=run([interpreter,'-c','import sys;compile(open(sys.argv[1],encoding="utf-8").read(),sys.argv[1],"exec")',str(target)])
        syntax_result=bool(result and result.returncode==0)
        if not syntax_result:issues.append(f'Generated file syntax failed: {target.name}');actions.append('Regenerate that submission with a supported interpreter.')
    else:issues.append('No generated submission exists yet for syntax checking.');actions.append('Generate a practice submission, then run readiness again.')
    fatal=not (supported and source_ok and root_write and output_write and stdlib_smoke) or syntax_result is False
    status='NOT READY' if fatal else 'READY WITH LIMITATIONS' if issues else 'READY'
    return {'status':status,'python':selected['executable'] if selected else interpreter,
            'version':'.'.join(str(x) for x in selected['version']) if selected else 'not found','implementation':implementation,
            'pip':pip_ok,'venv':venv_ok,'cryptography_version':cryptography_version,'cryptography_compatible':crypto_ok,
            'source_access':source_ok,'toolkit_writable':root_write,'output_writable':output_write,
            'generated_syntax':syntax_result,'stdlib_smoke':stdlib_smoke,'crypto_smoke':crypto_smoke,'network_smoke':network_smoke,
            'issues':issues,'actions':actions,'detected':discovered()}

def main():
    result=check()
    print('\nEXAM PC STATUS:',result['status'])
    print('Selected Python:',result['python'],'version',result['version'],'('+result['implementation']+')')
    print('Detected interpreters:',', '.join(f"{i['version'][0]}.{i['version'][1]} {i['executable']}" for i in result['detected']) or 'none')
    for label,key in [('pip available','pip'),('venv creation','venv'),('cryptography compatible','cryptography_compatible'),
                      ('source files','source_access'),('toolkit writable','toolkit_writable'),('output writable','output_writable'),
                      ('generated syntax','generated_syntax'),('standard-library smoke','stdlib_smoke'),('cryptography smoke','crypto_smoke'),('networked-record smoke','network_smoke')]:
        value=result[key];print(label+':', 'NOT TESTED' if value is None else 'YES' if value else 'NO')
    print('cryptography version:',result['cryptography_version'] or 'not importable')
    for issue,action in zip(result['issues'],result['actions']):print('ISSUE:',issue,'\nNEXT ACTION:',action)
    print('Python for all builder families: CPython 3.10-3.14; preferred/tested here: 3.12.')
    print('Crypto families need cryptography>=41,<51. Hash-only Custom builds use the standard library.')
    return 0 if result['status']!='NOT READY' else 1

if __name__=='__main__':raise SystemExit(main())
