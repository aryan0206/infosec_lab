"""Terminal guide to tested one-file submissions. Matching is advisory, not grading."""
import re
import subprocess
import sys
from pathlib import Path

from check_setup import inspect_environment

ROOT=Path(__file__).resolve().parent

SUBMISSIONS=(
    {
        'name':'RSA encrypted product',
        'path':'standalone_submissions/generated/rsa_product.py',
        'dependency':False,
        'inputs':'Exam RSA p,q,e or N,e,d; number of boxes and cost, each in 1..N-1.',
        'data':'No data or key files are created.',
        'coverage':(
            ('FULL','Menu, bounds, separate RSA encryption, ciphertext-only multiplication, final decryption.'),
            ('PARTIAL','Ordinary product equals the decrypted result only when it does not wrap modulo N; supplied N,e,d receive sample checks.'),
        ),
        'limits':'Textbook RSA exercise only; no OAEP or other requested mechanisms.',
    },
    {
        'name':'Paillier integer sum',
        'path':'standalone_submissions/paillier_sum.py',
        'dependency':True,
        'inputs':'Comma-separated nonnegative integers whose total is below Paillier n.',
        'data':'No data or key files are created.',
        'coverage':(
            ('FULL','Encrypt integers, combine ciphertexts, decrypt and compare the final sum.'),
            ('UNSUPPORTED','Records, signatures, search, role access and persistence are not in this generic file.'),
        ),
        'limits':'A mechanism template, not a complete patient or grant solution.',
    },
    {
        'name':'Patient records',
        'path':'standalone_submissions/generated/patient_records.py',
        'dependency':True,
        'inputs':'A supplied JSON list or CSV file with ID, name, diagnosis, glucose and treatment; choose L to import.',
        'data':'Creates demo_data/patients beside this script; retain records and keys for restart.',
        'coverage':(
            ('FULL','Named files, AES, SHA-256 by ID, RSA signing/verification, Paillier glucose sum, verified search/decrypt.'),
            ('FULL','Past-question menu numbering: 1..8 operations and 9 Exit; L imports the supplied dataset.'),
            ('PARTIAL','The supplied dataset must be available as JSON or CSV; a paper-only dataset still needs conversion.'),
        ),
        'limits':'Import only into an empty patient directory. Local teaching keys; display-dataset reads the requested plaintext file.',
    },
    {
        'name':'Grant expense portal',
        'path':'standalone_submissions/generated/grant_portal.py',
        'dependency':True,
        'inputs':'Grant ID, description, integer amount 0..1,000,000,000,000; selected IDs for finance.',
        'data':'Creates demo_data/grants beside this script; retain records and keys for restart.',
        'coverage':(
            ('FULL','AES-192 description, Paillier amount, MD5/RSA checks, encrypted persistent view, reviewer search/hex, selected aggregate.'),
            ('PARTIAL','Role menus have no authenticated identity; the finance range check relies on the local submission path.'),
            ('UNSUPPORTED','A cryptographic range proof and enforced user access control.'),
        ),
        'limits':'MD5 is collision-unsafe but specified. Older unbounded grants cannot enter finance aggregation.',
    },
    {
        'name':'E-voting educational demonstration',
        'path':'standalone_submissions/generated/e_voting_demo.py',
        'dependency':True,
        'inputs':'ISO UTC start/end, candidate count, ballot ID, candidate ID, constituency; demo tally codes A and B.',
        'data':'Creates demo_data/voting beside this script; first RSA-4096 key generation can take time.',
        'coverage':(
            ('PARTIAL','Demonstrates SHA-512, AES-256-CBC, RSA-4096 wrapping, toy ElGamal, Paillier counts and deadline checks.'),
            ('PARTIAL','Ballot is an in-memory record; token/time search is not formal searchable encryption.'),
            ('UNSUPPORTED','Trusted timestamp authority, bound voter identities, authenticated roles and true threshold Paillier.'),
        ),
        'limits':'Educational only; does not fully satisfy the original voting question.',
    },
    {
        'name':'ElGamal encrypted product',
        'path':'standalone_submissions/elgamal_product.py',
        'dependency':False,
        'inputs':'Toy prime p, generator g, optional private x; two integers in 1..p-1.',
        'data':'No data or key files are created.',
        'coverage':(
            ('FULL','ElGamal encryption of both inputs, ciphertext-only multiplication, final decryption and modular verification.'),
            ('PARTIAL','Ordinary product matches only below p; small trial-division parameters are educational.'),
        ),
        'limits':'One-file Lab 7 exercise, not a production ElGamal implementation.',
    },
)

EXTRA_REQUIREMENTS=(
    (r'\bctr\b','AES-CTR is not supplied by these one-file submissions.'),
    (r'\bschnorr\b','Schnorr signatures are not supplied by these one-file submissions.'),
    (r'\bpkse\b|paillier.{0,25}search','Formal Paillier searchable encryption is not supplied.'),
    (r'\bthreshold\b','True threshold decryption is not supplied.'),
    (r'trusted.{0,15}timestamp|timestamp.{0,15}authority','A trusted timestamp authority is not supplied.'),
)

def find_submissions(wording):
    """Rank known standalone patterns; do not infer completeness from keywords."""
    text=wording.casefold()
    scores=[0]*len(SUBMISSIONS)
    if re.search(r'\b(boxes?|cost)\b',text):scores[0]+=6
    if 'rsa' in text and re.search(r'multipl|product',text):scores[0]+=5
    if 'encrypted' in text and re.search(r'multipl|product',text):scores[0]+=2
    if re.search(r'\bpaillier\b|\bpallier\b',text) and re.search(r'\bsum\b|\badd|\btotal\b|aggregat',text):scores[1]+=5
    if 'encrypted' in text and re.search(r'\bsum\b|\badd',text):scores[1]+=2
    if re.search(r'patient|diagnos|blood.glucose',text):scores[2]+=8
    if re.search(r'grant|researcher|finance.officer',text):scores[3]+=8
    if re.search(r'vot|ballot|election',text):scores[4]+=8
    if 'elgamal' in text and re.search(r'multipl|product',text):scores[5]+=8
    return [SUBMISSIONS[i] for i in sorted(range(len(scores)),key=lambda i:-scores[i]) if scores[i]]

def route(wording):
    """Retain the simple path/note interface for existing navigation callers."""
    return [(item['path'],item['limits']) for item in find_submissions(wording)]

def command_for(item):
    return subprocess.list2cmdline([sys.executable,'-B',str(ROOT/item['path'])])

def preview(item,wording=''):
    print('\nClosest file:',ROOT/item['path'])
    print('Launch command:',command_for(item))
    print('Dependency:','Python 3.10+ and cryptography>=41' if item['dependency'] else 'Python 3.10+ standard library only')
    print('Required inputs:',item['inputs'])
    print('Persistence:',item['data'])
    print('Requirement coverage (for the documented pattern):')
    for status,detail in item['coverage']:print(f'  {status}: {detail}')
    for pattern,detail in EXTRA_REQUIREMENTS:
        if re.search(pattern,wording.casefold()):print('  UNSUPPORTED extra:',detail)
    print('Limitations:',item['limits'])
    print('Compare every line of your question with the checklist; phrase matching cannot certify a new question.')

def preflight(item):
    errors=inspect_environment(require_cryptography=item['dependency'])
    path=ROOT/item['path']
    if not path.is_file():errors.append(f'Missing submission: {path}')
    if not errors and '/generated/' in item['path']:
        check=subprocess.run([sys.executable,'-B',str(ROOT/'tools/build_submissions.py'),'--check'],
                             cwd=ROOT,capture_output=True,text=True)
        if check.returncode:
            errors.append((check.stdout+check.stderr).strip() or 'Generated submission check failed')
            errors.append('Regenerate with: '+subprocess.list2cmdline([sys.executable,'-B',str(ROOT/'tools/build_submissions.py')]))
    return errors

def offer_launch(item,wording=''):
    preview(item,wording)
    errors=preflight(item)
    if errors:
        for error in errors:print('Cannot launch:',error)
        return False
    if input('Launch this exact file now? [y/N]: ').strip().casefold()!='y':
        print('Launch cancelled.')
        return False
    result=subprocess.run([sys.executable,'-B',str(ROOT/item['path'])],cwd=ROOT)
    print('Program exited with code',result.returncode)
    return result.returncode==0

def choose(items,wording=''):
    for i,item in enumerate(items,1):print(f"{i}. {item['name']}  [{item['path']}]")
    choice=input('Preview number, or Enter to go back: ').strip()
    if not choice:return
    if not choice.isdecimal() or not 1<=int(choice)<=len(items):
        print('Invalid choice; enter a listed number.')
        return
    offer_launch(items[int(choice)-1],wording)

def main():
    print('IS Lab Endsem - terminal submission guide')
    print('Interpreter:',sys.executable)
    while True:
        try:
            print('\n1 Describe question  2 Browse standalone files  0 Exit')
            choice=input('Choice: ').strip()
            if choice=='0':return
            if choice=='1':
                wording=input('Required operations / question wording: ').strip()
                if not wording:print('Enter the required operations first.');continue
                items=find_submissions(wording)
                if items:choose(items,wording)
                else:print('UNSUPPORTED: no one-file match. Check the requirement checklist; do not submit a development demo as standalone.')
            elif choice=='2':choose(SUBMISSIONS)
            else:print('Invalid choice; enter 1, 2 or 0.')
        except (EOFError,KeyboardInterrupt):
            print('\nExited without launching.')
            return

if __name__=='__main__':main()
