"""Numbered, offline builder for configurable one-file exam submissions."""
import ast
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from check_setup import inspect_environment, install_command
from tools.build_submissions import render_scenario
from general_builder import configure as configure_general, generate as generate_general, catalog_rows

ROOT=Path(__file__).resolve().parent
OUTPUT=ROOT/'exam_output'
SCENARIO=ROOT/'components'/'ledger_scenario.py'
STDLIB_SCENARIO=ROOT/'components'/'stdlib_ledger.py'
NETWORK_SCENARIO=ROOT/'components'/'network_record_scenario.py'
NETWORK_FEATURES={'tcp_framed','entity_keys','aes_gcm','rsa_oaep','paillier','replay','hmac_search','audit'}
CRYPTO_FEATURES={'aes','paillier','researcher_sig','reviewer_sig','aggregate','entity_keys','aes_gcm','rsa_oaep'}

# Each entry documents purpose, input, dependency, prerequisite and a real limit.
CATALOG={
 'aes':('AES-GCM encrypted descriptions (128/192/256-bit key)','UTF-8 description','cryptography>=41',(),'Confidentiality depends on local key-file protection.'),
 'paillier':('Paillier encrypted integer amounts','integer 0..1e12','cryptography>=41',(),'No cryptographic range proof.'),
 'sha256':('SHA-256 over canonical record fields','record fields','standard library',(),'Hash alone does not authenticate a writer.'),
 'sha512':('SHA-512 over canonical record fields','record fields','standard library',(),'Hash alone does not authenticate a writer.'),
 'md5':('MD5 over canonical record fields','record fields','standard library',(),'MD5 is collision-unsafe; choose only when required.'),
 'researcher_sig':('Researcher RSA-PSS signature','record hash','cryptography>=41',(),'Requires SHA-256 or MD5; local key does not prove a human identity.'),
 'reviewer_sig':('Separate reviewer RSA-PSS decision signature','decision and original record hash','cryptography>=41',('approval','researcher_sig'),'Local role menu does not authenticate reviewer.'),
 'approval':('Approve/reject with reasons and latest decision','Expense ID and reason','standard library',(),'Requires SHA-256 or MD5; a new explicit decision may reverse a rejection.'),
 'audit':('Append-only event sequence with SHA-256 hash links','submissions and decisions','standard library',(),'No external trusted anchor; a privileged attacker can recompute the whole chain.'),
 'search':('Search by Expense ID and show metadata','Expense ID','standard library',(),'Linear scan; metadata is plaintext.'),
 'aggregate':('Finance aggregate of distinct IDs in one project','IDs, Project ID, budget','standard library',('paillier',),'Final total is decrypted; no zero-knowledge range proof.'),
 'demo':('Optional E1/E2/E3 practice records','menu choice','standard library',(),'Practice records are not exam data.'),
 'roles':('Named workflow roles','menu choice','standard library',(),'Menus do not enforce authenticated access.'),
 'tcp_framed':('Loopback TCP sender/receiver with decimal length frames','JSON packet, port','standard library',('entity_keys','aes_gcm','rsa_oaep','paillier','replay','hmac_search','audit'),'One packet per connection; localhost only.'),
 'entity_keys':('Per-entity persistent RSA enrolment','unique entity ID','cryptography>=41',(),'Unencrypted local private keys; no human identity proof.'),
 'aes_gcm':('Fresh per-packet AES-GCM key, selectable 128/192/256 bits','UTF-8 note','cryptography>=41',(),'Key custody remains local.'),
 'rsa_oaep':('RSA-OAEP wrap of packet AES key','receiver public key','cryptography>=41',(),'Requires receiver private key to decrypt.'),
 'replay':('Persistent per-entity increasing sequence check','entity ID and sequence','standard library',(),'Sequences derive from accepted packet log; no distributed consensus.'),
 'hmac_search':('HMAC exact-keyword token with SHA-256/512 choice','normalized keyword','standard library',(),'Packet metadata exposes keyword; index also leaks equality/frequency.'),
}
ORDER=tuple(CATALOG)
LEDGER_ORDER=ORDER[:13]
BASE={'sha256','researcher_sig','search','audit'}
FULL=set(LEDGER_ORDER)-{'md5','sha512'}
FAMILIES={
 '1':('Secure records (ID, project, category, description, amount)','secure_records',{'aes','researcher_sig','search'},BASE|{'aes'},FULL),
 '2':('Grant / expense management','grant_expense',{'aes','paillier','researcher_sig','search','aggregate'},BASE|{'aes','paillier','aggregate'},FULL),
 '4':('Encrypted sum / financial aggregation','encrypted_aggregation',{'paillier','aggregate'}, {'paillier','sha256','aggregate'},FULL),
 '5':('Role-based approval workflow','approval_workflow',{'researcher_sig','reviewer_sig','approval','audit','search'},BASE|{'approval','reviewer_sig','roles'},FULL),
 '6':('General cryptographic application','custom_security_application',set(),BASE,FULL),
}
VOTING=ROOT/'standalone_submissions'/'generated'/'e_voting_demo.py'

def normalize(features,required=()):
    features=set(features)|set(required)
    if len(features & {'md5','sha256','sha512'})>1:raise ValueError('Choose one of SHA-256, SHA-512, or MD5.')
    changed=True
    while changed:
        before=set(features)
        for feature in tuple(features):
            if feature not in CATALOG:raise ValueError('Unknown feature: '+feature)
            features.update(CATALOG[feature][3])
        changed=features!=before
    if ('researcher_sig' in features or 'approval' in features) and not ({'sha256','sha512','md5'} & features):
        features.add('sha256')
    if len(features & {'md5','sha256','sha512'})>1:raise ValueError('Conflicting hash choices.')
    if features & (NETWORK_FEATURES-{'paillier','audit'}) and 'tcp_framed' not in features:
        raise ValueError('Network components require the framed TCP workflow.')
    if 'tcp_framed' in features and features-NETWORK_FEATURES:
        raise ValueError('Network workflow cannot be mixed with local-ledger options; choose hash/AES variants in network settings.')
    return features

def network_options(options=None):
    defaults={'aes_bits':256,'hash_name':'sha256','hmac_hash':'sha256',
              'roles':['Administrator','Sender','Receiver','Auditor'],
              'role_actions':None,
              'labels':{'entity':'Entity ID','group':'Group','timestamp':'UTC timestamp','keyword':'Keyword','count':'Count','note':'Note'},
              'port':49152,'max_count':1_000_000_000_000}
    value={**defaults,**(options or {})}
    if value['aes_bits'] not in (128,192,256):raise ValueError('AES-GCM bits must be 128, 192, or 256')
    if value['hash_name'] not in ('sha256','sha512') or value['hmac_hash'] not in ('sha256','sha512'):
        raise ValueError('Supported SHA choices are SHA-256 and SHA-512')
    if type(value['port']) is not int or not 1024<=value['port']<=65535:raise ValueError('TCP port must be 1024..65535')
    if type(value['max_count']) is not int or not 0<value['max_count']<=1_000_000_000_000:
        raise ValueError('Maximum count must be 1..1000000000000')
    roles=value['roles']
    if not isinstance(roles,list) or not 1<=len(roles)<=8 or any(not isinstance(r,str) or not r.strip() for r in roles) or len(set(roles))!=len(roles):
        raise ValueError('Enter 1..8 distinct nonempty role names')
    if value['role_actions'] is None:
        if len(roles)!=4:raise ValueError('Custom role count needs an operation map')
        value['role_actions']={roles[0]:[1,2],roles[1]:[3],roles[2]:[4],roles[3]:[5,6,7]}
    action_map=value['role_actions']
    if not isinstance(action_map,dict) or set(action_map)!=set(roles) or any(
        not isinstance(actions,list) or not actions or any(type(action) is not int or action not in range(1,8) for action in actions)
        for actions in action_map.values()):raise ValueError('Each role needs operation numbers 1..7')
    labels=value['labels']
    if not isinstance(labels,dict) or set(labels)!={'entity','group','timestamp','keyword','count','note'} or any(not isinstance(v,str) or not v.strip() for v in labels.values()):
        raise ValueError('Enter six nonempty field labels')
    return value

def local_options(features,options=None):
    value={'aes_bits':192,**(options or {})}
    if set(value)!={'aes_bits'}:raise ValueError('Unknown local-record setting')
    if value['aes_bits'] not in (128,192,256):raise ValueError('AES-GCM bits must be 128, 192, or 256')
    if 'aes' not in features and options:raise ValueError('AES setting requires AES feature')
    return value

def choose_network_options():
    print('Network settings (press Enter for each shown default).')
    try:
        aes=input('AES-GCM key bits [256] (128/192/256): ').strip() or '256'
        hash_name=input('RSA signature/OAEP SHA [256] (256/512): ').strip() or '256'
        hmac_hash=input('HMAC search SHA [256] (256/512): ').strip() or '256'
        roles=input('Role names, comma-separated [Administrator,Sender,Receiver,Auditor]: ').strip()
        chosen_roles=[r.strip() for r in roles.split(',')] if roles else ['Administrator','Sender','Receiver','Auditor']
        print('Operations: 1 Enrol  2 Set up keys  3 Send  4 Receive  5 Search  6 Decrypt note  7 Aggregate')
        mapping=input('Role operations as semicolon groups [1,2;3;4;5,6,7]: ').strip()
        role_actions=None
        if mapping:
            groups=mapping.split(';')
            if len(groups)!=len(chosen_roles):raise ValueError('Provide one operation group per role')
            role_actions={role:[int(part.strip()) for part in group.split(',')] for role,group in zip(chosen_roles,groups)}
        fields=input('Field labels: entity, group, UTC time, keyword, count, note [Entity ID,Group,UTC timestamp,Keyword,Count,Note]: ').strip()
        field_names=[v.strip() for v in fields.split(',')] if fields else ['Entity ID','Group','UTC timestamp','Keyword','Count','Note']
        if len(field_names)!=6:raise ValueError('Enter six comma-separated field labels')
        max_count=input('Maximum count per packet [1000000000000]: ').strip() or '1000000000000'
        port=input('Local TCP port [49152]: ').strip() or '49152'
        options={'aes_bits':int(aes),'hash_name':'sha'+hash_name,'hmac_hash':'sha'+hmac_hash,
                 'roles':chosen_roles,'role_actions':role_actions,
                 'labels':dict(zip(('entity','group','timestamp','keyword','count','note'),field_names)),
                 'port':int(port),'max_count':int(max_count)}
        return network_options(options)
    except ValueError as exc:print('Invalid network setting:',exc);return None

def new_path(stem):
    OUTPUT.mkdir(exist_ok=True)
    stamp=datetime.now().strftime('%Y%m%d_%H%M%S')
    path=OUTPUT/f'{stem}_{stamp}.py';number=2
    while path.exists():path=OUTPUT/f'{stem}_{stamp}_{number}.py';number+=1
    return path

def build(family_key,features,options=None):
    if family_key not in FAMILIES:raise ValueError('Unknown application family')
    label,stem,required,_,_=FAMILIES[family_key]
    selected=normalize(features,required)
    network='tcp_framed' in selected
    if network and family_key!='6':raise ValueError('Network workflow is available under General application only')
    configured=network_options(options) if network else local_options(selected,options)
    needs_crypto=bool(selected & CRYPTO_FEATURES)
    if not needs_crypto and selected & {'roles','demo'}:
        raise ValueError('Roles and demo records are unavailable in the standard-library-only profile; remove them or add a cryptographic feature.')
    errors=inspect_environment(require_cryptography=needs_crypto)
    if errors:raise ValueError('; '.join(errors))
    source=(render_scenario('networked_records',NETWORK_SCENARIO).decode('utf-8') if network else
            render_scenario('configurable_ledger',SCENARIO).decode('utf-8') if needs_crypto else STDLIB_SCENARIO.read_text(encoding='utf-8'))
    replacement='CONFIG = '+repr({'family':label,'features':sorted(selected),**(configured or {})})
    source,count=re.subn(r'^CONFIG = .*$',lambda _:replacement,source,count=1,flags=re.M)
    if count!=1:raise ValueError('Could not inject selected features')
    tree=ast.parse(source)
    if any((isinstance(n,ast.ImportFrom) and (n.level or n.module in {'core','store','master_builder'})) or
           (isinstance(n,ast.Import) and any(a.name in {'core','store','master_builder'} for a in n.names)) for n in ast.walk(tree)):
        raise ValueError('Output still imports project-local modules')
    if 'sys.path.insert(' in source:raise ValueError('Output still changes Python import paths')
    source=f'# Supported CPython: 3.10 through 3.14. Preferred/tested: 3.12.\n# Dependencies: {"cryptography>=41,<51" if needs_crypto else "Python standard library only"}.\n# Setup: {"use SETUP_REQUIREMENTS.bat in toolkit or install cryptography>=41,<51 in a local venv" if needs_crypto else "no package installation required"}.\n'+source
    path=new_path(stem)
    path.write_text(source,encoding='utf-8')
    report=path.with_suffix('.checklist.txt')
    lines=[f'Family: {label}',f'Submission: {path.name}',f'Enabled features: {", ".join(sorted(selected))}',
           'Implemented: '+', '.join(CATALOG[f][0] for f in ORDER if f in selected),
           'Partial: role menus do not authenticate people; local key files are unprotected; hash chain has no trusted external anchor.',
           'Missing/unsupported: arbitrary exam requirements outside this feature list are not implemented.',
           'Supported Python: CPython 3.10 through 3.14; preferred/tested here: 3.12',
           'Dependencies: '+('cryptography>=41,<51' if needs_crypto else 'standard library only'),
           'Install if needed: '+(install_command() if needs_crypto else 'No package installation required'),
           f'Run: {sys.executable} -B "{path}"',f'Runtime records and keys: {path.parent / "demo_data" / path.stem}',
           'At generation: syntax parsed and project-local imports checked. Functional test results, if run, are appended below.',
           'Review every requirement of the actual question before submission.']
    if network:
        lines += [f'Network settings: AES-{configured["aes_bits"]}-GCM; RSA/OAEP {configured["hash_name"]}; HMAC {configured["hmac_hash"]}; port {configured["port"]}',
                  f'Role labels: {", ".join(configured["roles"])}; field labels: {configured["labels"]}',
                  'Role operation map: '+repr(configured['role_actions']),
                  f'Maximum sender count: {configured["max_count"]}; aggregate by {configured["labels"]["group"]}.',
                  'Partial: Paillier count bound relies on enrolled sender input; there is no cryptographic range proof.',
                  'Partial: sender-provided UTC time is not a trusted timestamp; role menus are not authenticated.']
    else:
        lines.append(f'Local encryption: {"AES-"+str(configured["aes_bits"])+"-GCM" if "aes" in selected else "none"}; record hash: {next((x for x in ("sha256","sha512","md5") if x in selected),"none")}.')
    report.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    return path,report,selected

def validate(path):
    path=Path(path).resolve()
    if path.parent!=OUTPUT.resolve() or not path.is_file() or path.suffix!='.py':raise ValueError('Choose a generated .py file in exam_output')
    source=path.read_text(encoding='utf-8')
    tree=ast.parse(source)
    compile(source,str(path),'exec')
    if any(isinstance(n,ast.FunctionDef) and n.name=='self_test' for n in tree.body):
        result=subprocess.run([sys.executable,'-B',str(path),'--self-test'],cwd=OUTPUT,
                              capture_output=True,text=True,timeout=60)
        if result.returncode:raise ValueError('Functional self-test failed: '+(result.stdout+result.stderr).strip())
        if 'SELF-TEST PASSED' not in result.stdout:raise ValueError('Functional self-test did not report success')
        return 'Syntax and functional self-test PASSED (isolated records, restart, and applicable feature checks). Exam-specific review remains.'
    return 'Syntax passed. Functional self-test unavailable for this fixed template; run and review it manually.'

def display_catalog():
    print('Schema-driven generator (menu 10): configurable roles, field schemas, PIN login, AES-CBC/GCM 128/192/256,')
    print('SHA-2/SHA-3/MD5 digests, HMAC-SHA-256/512 search, RSA-PSS, Paillier sums, audit chain and JSON persistence.')
    print('Also selectable: RSA-OAEP wrapping, ElGamal signatures, Shamir reconstruction, loopback TCP, freshness, textbook RSA.')
    print('See COMPONENT_CATALOG.md for tested, partial and unsupported status.\n')
    for i,key in enumerate(ORDER,1):
        purpose,inputs,dependency,needs,limit=CATALOG[key]
        print(f'{i}. {key}: {purpose}')
        print(f'   Input: {inputs}; dependency: {dependency}; needs: {", ".join(needs) or "none"}')
        print('   Limit:',limit)
    from exam_router import SUBMISSIONS
    print('\nFixed examples also available for copying:')
    for i,item in enumerate(SUBMISSIONS,1):print(f'{i}. {item["name"]} - {item["limits"]}')

def review_templates():
    display_catalog()
    from exam_router import SUBMISSIONS,create_submission,preflight
    answer=input('Copy a fixed example? Enter its number, or 0 to return: ').strip()
    if answer=='0':return
    if not answer.isdecimal() or not 1<=int(answer)<=len(SUBMISSIONS):print('Invalid example number.');return
    item=SUBMISSIONS[int(answer)-1]
    print('Coverage:')
    for status,detail in item['coverage']:print(status+':',detail)
    if input('Create a NEW standalone copy? [Y/N]: ').strip().lower()!='y':return
    errors=preflight(item)
    if errors:
        for error in errors:print('Cannot copy:',error)
        return
    path,report=create_submission(item,'Fixed example selected from Master Builder; compare with actual question')
    postbuild(path,report)

def select_features(family_key):
    label,_,required,basic,full=FAMILIES[family_key]
    print('\n',label)
    print('Required:',', '.join(sorted(required)) or 'none')
    print('Signed records use SHA-256 by default; Custom can choose SHA-512 or MD5 if required.')
    print('1 Basic:',', '.join(sorted(normalize(basic,required))))
    print('2 Full:',', '.join(sorted(normalize(full,required))))
    print('3 Custom  0 Cancel')
    choice=input('Preset: ').strip()
    if choice=='0':return None
    if choice=='1':return normalize(basic,required)
    if choice=='2':return normalize(full,required)
    if choice!='3':print('Invalid preset.');return None
    choices=ORDER if family_key=='6' else LEDGER_ORDER
    for i,key in enumerate(choices,1):print(f'{i}. {key}'+(' [required]' if key in required else ''))
    raw=input('Optional feature numbers, comma-separated (Enter = required only): ').strip()
    chosen=set(required)
    if raw:
        for part in raw.split(','):
            if not part.strip().isdecimal() or not 1<=int(part.strip())<=len(choices):
                print('Invalid feature number; cancelled.');return None
            chosen.add(choices[int(part.strip())-1])
    try:return normalize(chosen,required)
    except ValueError as exc:print('Feature conflict:',exc);return None

def postbuild(path,report):
    print('\nNEW SUBMISSION:',path)
    print('CHECKLIST:',report)
    print(report.read_text(encoding='utf-8'))
    if input('Open output folder? [Y/N]: ').strip().lower()=='y':
        from exam_router import open_output
        open_output()
    if input('Run the new program? [Y/N]: ').strip().lower()=='y':
        result=subprocess.run([sys.executable,'-B',str(path)],cwd=path.parent)
        print('Program exit code:',result.returncode)
        with report.open('a',encoding='utf-8') as f:f.write(f'Interactive run attempted: exit code {result.returncode}; exam-specific behavior NOT certified.\n')
        if result.returncode:print('Next action: read the error above and check the checklist.')
    if input('Run validation tests? [Y/N]: ').strip().lower()=='y':
        try:
            message=validate(path);print(message)
            with report.open('a',encoding='utf-8') as f:f.write('Validation performed: '+message+'\n')
        except (OSError,ValueError,SyntaxError) as exc:print('Validation failed:',exc)

def choose_existing():
    files=sorted(OUTPUT.glob('*.py')) if OUTPUT.exists() else []
    if not files:print('No generated files yet. Build one first.');return
    for i,path in enumerate(files,1):print(f'{i}. {path.name}')
    answer=input('File number, or 0 to cancel: ').strip()
    if answer=='0':return
    if not answer.isdecimal() or not 1<=int(answer)<=len(files):print('Invalid file number.');return
    path=files[int(answer)-1]
    try:print(validate(path))
    except (ValueError,OSError,SyntaxError) as exc:print('Validation failed:',exc);return
    if input('Run this file? [Y/N]: ').strip().lower()=='y':
        result=subprocess.run([sys.executable,'-B',str(path)],cwd=OUTPUT)
        print('Program exit code:',result.returncode)

def main():
    print('IS Lab Endsem Master Builder')
    print('Choose a family, choose Basic/Full/Custom features, then create a new one-file submission.')
    print('Read the checklist. No pasted question is needed. Role menus are workflow examples, not login security.')
    while True:
        try:
            print('\n1 Secure records  2 Grant/expense  3 E-voting demo  4 Encrypted aggregation')
            print('5 Approval workflow  6 Legacy general example  7 Features/templates  8 Run/verify output  9 Open output folder')
            print('10 Build schema-driven application  11 Search component catalog  0 Exit')
            choice=input('Choice: ').strip()
            if choice=='0':return
            if choice=='10':
                try:
                    errors=inspect_environment(require_cryptography=True)
                    if errors:raise ValueError('; '.join(errors))
                    config=configure_general()
                    print('Configuration summary:',json.dumps(config,indent=2))
                    print('Limits: no prose conversion, external chain anchor, cryptographic range proof or remote secure TCP transport.')
                    if input('Generate this application? [Y/N]: ').strip().lower()!='y':continue
                    path,report=generate_general(config,new_path('general_application'))
                    if config.get('architecture')=='tcp_client_server':
                        print('SERVER:',path.with_name(path.stem+'_server.py'))
                        print('CLIENT:',path.with_name(path.stem+'_client.py'))
                        print('Start the server first in one terminal, then run the client in another.')
                    postbuild(path,report)
                except (ValueError,OSError,SyntaxError) as exc:print('General build failed:',exc)
            elif choice=='11':
                term=input('Search algorithm, operation, dependency or status (Enter = all): ')
                rows=catalog_rows(term)
                if not rows:print('No component matches that search.')
                for name,operations,dependency,status in rows:
                    print(f'{name}: {status}\n  Operations: {operations}; dependency: {dependency}')
            elif choice in FAMILIES:
                selected=select_features(choice)
                if selected is None:continue
                options=choose_network_options() if 'tcp_framed' in selected else None
                if 'tcp_framed' in selected and options is None:continue
                if 'aes' in selected:
                    try:options=local_options(selected,{'aes_bits':int(input('AES-GCM key bits [192] (128/192/256): ').strip() or '192')})
                    except ValueError as exc:print('Invalid AES selection:',exc);continue
                print('Enabled:',', '.join(sorted(selected)))
                if input('Generate this combination? [Y/N]: ').strip().lower()!='y':print('Cancelled.');continue
                try:path,report,_=build(choice,selected,options);postbuild(path,report)
                except (OSError,ValueError,SyntaxError) as exc:print('Build failed:',exc,'\nNext action: adjust features or install the required dependency.')
            elif choice=='3':
                print('Voting is a fixed educational template. Trusted timestamp authority, voter identity binding, and threshold Paillier are unsupported.')
                if input('Copy voting demo to a new file? [Y/N]: ').strip().lower()!='y':continue
                from exam_router import create_submission,SUBMISSIONS
                path,report=create_submission(SUBMISSIONS[4],'Educational voting demonstration; unsupported features listed in checklist')
                postbuild(path,report)
            elif choice=='7':review_templates()
            elif choice=='8':choose_existing()
            elif choice=='9':
                from exam_router import open_output
                open_output()
            else:print('Invalid choice; choose a listed number.')
        except (EOFError,KeyboardInterrupt):print('\nExited.');return

if __name__=='__main__':main()
