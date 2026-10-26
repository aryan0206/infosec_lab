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
    if sys.version_info<(3,10):errors.append('Python 3.10 or newer is required')
    if require_cryptography:
        try:
            import cryptography
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            version=tuple(int(piece) for piece in cryptography.__version__.split('.')[:2])
            if version<(41,0):errors.append('cryptography>=41 is required; install with: '+install_command())
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
    print('READY: run',subprocess.list2cmdline([sys.executable,'-B',str(ROOT/'exam_router.py')]))
    return 0

if __name__=='__main__':raise SystemExit(main())
