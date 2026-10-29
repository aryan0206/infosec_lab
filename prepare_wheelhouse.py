"""Download binary dependencies for a stated Windows target; does not install them."""
import argparse
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--python',required=True,choices=['3.10','3.11','3.12','3.13','3.14'],help='target CPython minor version')
    parser.add_argument('--platform',required=True,choices=['win_amd64','win_arm64','win32'],help='target wheel platform')
    args=parser.parse_args()
    dest=ROOT/'wheelhouse'
    dest.mkdir(exist_ok=True)
    version=args.python.replace('.','')
    command=[sys.executable,'-m','pip','download','--only-binary=:all:','--implementation','cp',
             '--python-version',version,'--platform',args.platform,'--abi','cp'+version,'--abi','abi3','--abi','none',
             '--dest',str(dest),'-r',str(ROOT/'requirements.txt')]
    print('Target: Windows',args.platform,'CPython',args.python,'ABI cp'+version+'/abi3; NOT portable to other targets.')
    print('Downloading package and transitive binary wheels to',dest)
    outcome=subprocess.run(command,cwd=ROOT)
    if outcome.returncode:
        print('Download failed. Do not assume offline setup is ready. Check target tags and internet access.');return 1
    wheels=sorted(dest.glob('*.whl'))
    manifest={'target_platform':args.platform,'target_python':args.python,'abi':['cp'+version,'abi3','none'],
              'prepared_with':sys.executable,'wheels':[{'file':p.name,'package':p.name.split('-')[0],
              'version':p.name.split('-')[1],'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in wheels]}
    (dest/'MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    print('Downloaded',len(wheels),'wheels. Test offline installation on the target architecture before relying on them.')
    return 0

if __name__=='__main__':raise SystemExit(main())
