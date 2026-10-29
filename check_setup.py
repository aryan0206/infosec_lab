"""Check the selected Python runtime; cryptography is optional for RSA only."""
import argparse
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent

def install_command():
    return subprocess.list2cmdline([sys.executable,'-m','pip','install','-r',str(ROOT/'requirements.txt')])

def inspect_environment(require_cryptography=False):
    errors=[]
    if not (3,10)<=sys.version_info[:2]<=(3,14):errors.append('Supported CPython versions are 3.10 through 3.14; use 3.12 if available')
    if require_cryptography:
        try:
            import cryptography
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            version=tuple(int(piece) for piece in cryptography.__version__.split('.')[:2])
            if not (41,0)<=version<(51,0):errors.append('cryptography>=41,<51 is required; install with: '+install_command())
        except (ImportError,ValueError) as exc:
            errors.append(f'cryptography is missing or unusable ({exc}); install with: {install_command()}')
    return errors

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-cryptography',action='store_true',help='fail if integrated submissions cannot run')
    args=parser.parse_args()
    print('Python executable:',sys.executable)
    print('Python version:',sys.version.split()[0])
    errors=inspect_environment(args.require_cryptography)
    for error in errors:print('MISSING:',error)
    if errors:return 1
    if not args.require_cryptography:
        dependency_errors=inspect_environment(True)
        if dependency_errors:
            print('RSA product is available; cryptography-dependent submissions are unavailable:')
            for error in dependency_errors:print('  ',error)
        else:print('cryptography: ready')
    print('READY: run',subprocess.list2cmdline([sys.executable,'-B',str(ROOT/'master_builder.py')]))
    return 0

if __name__=='__main__':raise SystemExit(main())
