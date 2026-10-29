"""Interactive configuration and source generation for the schema-driven engine."""
import ast
import json
import re
import ipaddress
from pathlib import Path

ENGINE=Path(__file__).resolve().parent/'components'/'general_application.py'
OPS=('submit','view','verify','search','approve','decrypt','aggregate','keys','rsa_product','hex_dump','serve','send')
COMPONENTS={
 'AES-CBC/GCM 128/192/256':('encrypt,decrypt','cryptography','CBC-128 and GCM-128/192/256 tested; other CBC sizes partial'),
 'SHA-1/224/256/384/512; SHA3-224/256/384/512; MD5':('digest','hashlib','SHA-256 and SHA3-256 generated-app tested; remaining variants partial; SHA-1/MD5 collision-unsafe'),
 'HMAC-SHA-256/512':('exact search token','hashlib, searchable field','both variants tested'),
 'RSA-OAEP SHA-256':('per-record AES key wrap,unwrap','RSA key, AES field','tested'),
 'RSA-PSS':('sign,verify','RSA key, canonical digest','2048 tested; 3072/4096 partial'),
 'ElGamal signature':('sign,verify','runtime prime,key','512 tested; 1024 partial; base-2 order unproven'),
 'Schnorr signature':('sign,verify','runtime DSA group,key','1024 tested; 2048/3072 partial'),
 'Textbook RSA':('encrypted multiplication','RSA key','tested; educational only'),
 'Paillier':('encrypt,sum,weighted sum,scalar multiply,mean','integer field, key','1024 tested; 2048 partial'),
 'Shamir':('split,reconstruct','Paillier decryption secret','2-of-3 tested; local reconstruction only'),
 'Audit/replay/freshness':('canonical hash chain,nonce check,time window','JSON persistence','tested; no external anchor or trusted time'),
 'TCP client/server':('send,serve,framed JSON','IPv4 host,port,roles','separate processes and concurrent clients tested; no TLS'),
 'UDP':('client,server','none','unsupported; not found in audited Lab 5 manual'),
 'Multipart transfer':('reassemble,verify','network framing','unsupported in option 10; Lab 5 additional exercise'),
 'Diffie-Hellman':('key agreement','group parameters','unsupported in option 10; Lab 6 exercise'),
 'ElGamal homomorphic multiplication':('encrypted product','ElGamal encryption','unsupported in option 10; standalone exercise exists'),
 'GnuPG/Snort':('external command/tool workflows','system tools','unsupported as generated Python components'),
}

def catalog_rows(query=''):
    query=query.casefold().strip()
    return [(name,*details) for name,details in COMPONENTS.items() if not query or query in (' '.join((name,*details))).casefold()]

def validate_config(config):
    fields=config['fields'];roles=config['roles']
    if not fields or not roles:raise ValueError('At least one field and one role are required')
    names=[f['name'] for f in fields]
    if len(names)!=len(set(names)) or any(not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*',n) for n in names):raise ValueError('Field names must be unique identifiers')
    if any(f['type'] not in ('text','integer','boolean') for f in fields):raise ValueError('Unsupported data type')
    for field in fields:
        if field['type']=='text' and (field.get('min_length',0)<0 or field.get('max_length',1000)<field.get('min_length',0)):
            raise ValueError('Invalid text length constraints')
        if field['type']=='integer' and field.get('max',10**12)<field.get('min',-10**12):
            raise ValueError('Invalid integer bounds')
    if any(f.get('encrypted') for f in fields) and config['encryption']=='none':raise ValueError('Encrypted fields require AES')
    if config['encryption'] not in ('none','CBC','GCM') or config['aes_bits'] not in (128,192,256):raise ValueError('Unsupported AES choice')
    if config['hash'] not in ('sha1','sha224','sha256','sha384','sha512','sha3_224','sha3_256','sha3_384','sha3_512','md5'):raise ValueError('Unsupported hash')
    if config['hmac_hash'] not in ('sha256','sha512'):raise ValueError('Unsupported HMAC')
    if config['signature'] not in ('none','rsa_pss','elgamal','schnorr') or config['rsa_bits'] not in (2048,3072,4096):raise ValueError('Unsupported signature or RSA size')
    if config.get('elgamal_bits',512) not in (512,1024):raise ValueError('ElGamal prime bits must be 512 or 1024')
    if config.get('schnorr_bits',2048) not in (1024,2048,3072):raise ValueError('Schnorr DSA group bits must be 1024, 2048 or 3072')
    if config.get('key_wrapping',False) and (config['encryption']=='none' or not any(f.get('encrypted') for f in fields)):
        raise ValueError('RSA-OAEP key wrapping needs an AES encrypted field')
    if config.get('shamir'):
        sharing=config['shamir']
        if not config['aggregate_field']:raise ValueError('Shamir requires Paillier aggregation')
        if type(sharing.get('threshold')) is not int or type(sharing.get('shares')) is not int or not 2<=sharing['threshold']<=sharing['shares']<=8:
            raise ValueError('Shamir requires 2 <= threshold <= shares <= 8')
    if type(config.get('freshness_seconds',0)) is not int or not 0<=config.get('freshness_seconds',0)<=86400:
        raise ValueError('Freshness window must be 0..86400 seconds')
    if config.get('tcp_port') is not None and (type(config['tcp_port']) is not int or not 1024<=config['tcp_port']<=65535):
        raise ValueError('TCP port must be 1024..65535')
    architecture=config.get('architecture','tcp_client_server' if config.get('tcp_port') else 'standalone')
    if architecture not in ('standalone','tcp_client_server'):raise ValueError('Unsupported architecture; UDP is not implemented')
    if (architecture=='tcp_client_server')!=(config.get('tcp_port') is not None):raise ValueError('TCP architecture requires a port; standalone must omit it')
    try:ipaddress.IPv4Address(config.get('tcp_host','127.0.0.1'))
    except ValueError as exc:raise ValueError('TCP host must be an IPv4 address') from exc
    if config['aggregate_field'] and (config['aggregate_field'] not in names or next(f for f in fields if f['name']==config['aggregate_field'])['type']!='integer'):
        raise ValueError('Aggregate field must be an integer field')
    if config['aggregate_field'] and next(f for f in fields if f['name']==config['aggregate_field']).get('encrypted'):
        raise ValueError('Aggregate field uses Paillier; do not also select AES encryption')
    if config['aggregate_field'] and next(f for f in fields if f['name']==config['aggregate_field']).get('min',0)<0:raise ValueError('Aggregate field must be nonnegative')
    if config['aggregate_field'] and not next(f for f in fields if f['name']==config['aggregate_field']).get('required',True):raise ValueError('Aggregate field must be required')
    if config['paillier_bits'] not in (1024,2048):raise ValueError('Supported Paillier sizes are 1024 and 2048')
    for name,policy in roles.items():
        if not name.strip() or not set(policy['operations'])<=set(OPS):raise ValueError('Invalid role or operation')
        if policy['access'] not in ('all','own'):raise ValueError('Unsupported access rule')
        if set(policy.get('view_fields',[]))-set(names) or set(policy.get('decrypt_fields',[]))-set(names):raise ValueError('Unknown field in permissions')
        if policy.get('condition'):
            condition_field=next((f for f in fields if f['name']==policy['condition']['field']),None)
            if not condition_field:raise ValueError('Unknown condition field')
            if condition_field.get('encrypted') or condition_field['name']==config['aggregate_field']:
                raise ValueError('Record condition requires a plaintext field')
        if 'aggregate' in policy['operations'] and not config['aggregate_field']:raise ValueError('Aggregate operation needs aggregate field')
        if 'decrypt' in policy['operations'] and not policy.get('decrypt_fields'):raise ValueError('Decrypt operation needs allowed fields')
        if 'hex_dump' in policy['operations'] and ('decrypt' not in policy['operations'] or not policy.get('decrypt_fields')):raise ValueError('Hex dump needs decrypt permission and fields')
        if any(not next(f for f in fields if f['name']==selected).get('encrypted') for selected in policy.get('decrypt_fields',[])):
            raise ValueError('Decrypt permission requires AES encrypted fields')
        if 'search' in policy['operations'] and not any(f.get('searchable') for f in fields):raise ValueError('Search operation needs a searchable field')
        if 'rsa_product' in policy['operations'] and not config.get('textbook_rsa'):raise ValueError('RSA product component not selected')
        if set(policy['operations']) & {'serve','send'} and config.get('tcp_port') is None:raise ValueError('TCP operation needs a port')
        if 'send' in policy['operations'] and 'submit' not in policy['operations']:raise ValueError('TCP sender also needs submit permission')
    selected_ops={op for policy in roles.values() for op in policy['operations']}
    if config.get('textbook_rsa') and 'rsa_product' not in selected_ops:raise ValueError('Textbook RSA selected but no role can use it')
    if config.get('tcp_port') is not None and not {'send','serve'}<=selected_ops:raise ValueError('TCP needs send and serve roles')
    if config.get('shamir') and 'aggregate' not in selected_ops:raise ValueError('Shamir selected but no role can aggregate')
    return config

def ask(prompt,default=''):
    value=input(prompt+(' ['+str(default)+']' if default!='' else '')+': ').strip()
    return value if value else str(default)

def yes(prompt,default=False):
    return ask(prompt,'Y' if default else 'N').lower() in ('y','yes')

def configure():
    print('General generator: enter role names and fields as data. Supported operations:',', '.join(OPS))
    title=ask('Application title','Custom records')
    fields=[]
    count=int(ask('Number of fields','2'))
    for i in range(count):
        print('Field',i+1)
        name=ask('Internal field name (letters/digits/underscore)')
        label=ask('Display label',name)
        kind=ask('Type text/integer/boolean','text').lower()
        field={'name':name,'label':label,'type':kind,'required':yes('Required',True)}
        if kind=='text':
            field['min_length']=int(ask('Minimum length','0'));field['max_length']=int(ask('Maximum length','1000'))
            choices=ask('Allowed choices, comma separated (empty means any)')
            if choices:field['choices']=[x.strip() for x in choices.split(',')]
        elif kind=='integer':field['min']=int(ask('Minimum integer','0'));field['max']=int(ask('Maximum integer','1000000'))
        field['encrypted']=yes('Encrypt this field with AES')
        field['searchable']=yes('Exact HMAC search index')
        fields.append(field)
    encryption=ask('AES mode none/CBC/GCM','GCM').upper()
    if encryption=='NONE':encryption='none'
    aes_bits=int(ask('AES key size 128/192/256','256'))
    hash_name=ask('Record hash (sha1/sha224/sha256/sha384/sha512/sha3_*/md5)','sha256').lower()
    hmac_hash=ask('HMAC hash sha256/sha512','sha256').lower()
    signature=ask('Signature none/rsa_pss/elgamal/schnorr','rsa_pss').lower()
    rsa_bits=int(ask('RSA bits 2048/3072/4096','2048'))
    aggregate_field=ask('Paillier aggregate field name (empty disables)') or None
    paillier_bits=int(ask('Paillier bits 1024/2048','1024'))
    key_wrapping=yes('Fresh per-record AES key with RSA-OAEP wrapping')
    elgamal_bits=int(ask('ElGamal prime bits 512/1024','512'))
    schnorr_bits=int(ask('Schnorr group bits 1024/2048/3072','2048')) if signature=='schnorr' else 2048
    threshold=int(ask('Shamir threshold (0 disables)','0'))
    shamir={'threshold':threshold,'shares':int(ask('Number of Shamir shares','3'))} if threshold else None
    freshness_seconds=int(ask('Freshness window in seconds (0 disables)','0'))
    textbook_rsa=yes('Enable textbook RSA multiplication exercise')
    tcp_text=ask('TCP port (empty selects standalone)')
    tcp_port=int(tcp_text) if tcp_text else None
    architecture=ask('Architecture standalone/tcp_client_server','tcp_client_server' if tcp_port else 'standalone').lower()
    tcp_host=ask('TCP IPv4 host','127.0.0.1') if architecture=='tcp_client_server' else '127.0.0.1'
    roles={}
    for i in range(int(ask('Number of roles','2'))):
        name=ask('Role '+str(i+1)+' name')
        operations=[x.strip().lower() for x in ask('Allowed operations, comma separated').split(',') if x.strip()]
        role={'operations':operations,'auth':yes('Require PIN authentication'),'access':ask('Record access all/own','all').lower()}
        view=ask('Visible field names, comma separated (empty = all)')
        role['view_fields']=[x.strip() for x in view.split(',') if x.strip()]
        decrypt=ask('Fields permitted for decrypt, comma separated')
        role['decrypt_fields']=[x.strip() for x in decrypt.split(',') if x.strip()]
        condition=ask('Record condition field (empty = none)')
        if condition:
            field=next((f for f in fields if f['name']==condition),None)
            if not field:raise ValueError('Unknown condition field')
            required=ask('Required value for '+condition)
            if field['type']=='integer':required=int(required)
            elif field['type']=='boolean':required=required.lower() in ('y','yes','true','1')
            role['condition']={'field':condition,'equals':validate_value_for_condition(field,required)}
        if name in roles:raise ValueError('Duplicate role name')
        roles[name]=role
    return validate_config({'title':title,'fields':fields,'roles':roles,'encryption':encryption,
        'aes_bits':aes_bits,'hash':hash_name,'hmac_hash':hmac_hash,'signature':signature,
        'rsa_bits':rsa_bits,'aggregate_field':aggregate_field,'paillier_bits':paillier_bits,
        'key_wrapping':key_wrapping,'elgamal_bits':elgamal_bits,'schnorr_bits':schnorr_bits,'shamir':shamir,
        'freshness_seconds':freshness_seconds,'textbook_rsa':textbook_rsa,'tcp_port':tcp_port,
        'architecture':architecture,'tcp_host':tcp_host})

def validate_value_for_condition(field,value):
    if field['type']=='text' and not isinstance(value,str):raise ValueError('Condition must be text')
    if field['type']=='integer' and type(value) is not int:raise ValueError('Condition must be integer')
    if field['type']=='boolean' and type(value) is not bool:raise ValueError('Condition must be boolean')
    return value

def generate(config,output):
    validate_config(config)
    source=ENGINE.read_text(encoding='utf-8')
    source=source.replace('CONFIG = {}','CONFIG = '+repr(config),1)
    ast.parse(source)
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(source,encoding='utf-8')
    launchers=[]
    if config.get('architecture')=='tcp_client_server':
        for kind in ('server','client'):
            script=output.with_name(output.stem+'_'+kind+'.py')
            wrapper=f'from {output.stem} import {kind}_main\n\nif __name__ == "__main__":\n    {kind}_main()\n'
            ast.parse(wrapper)
            script.write_text(wrapper,encoding='utf-8')
            launchers.append(script)
    report=output.with_suffix('.checklist.txt')
    report.write_text('General schema-driven application\nConfiguration:\n'+json.dumps(config,indent=2)+'\n'
        +'Runtime files: demo_data/<generated name>/records.json, keys.json, and selected PEM, Shamir shares and PIN account files.\n'
        +'Limits: local key files are unprotected; PINs authenticate a shared role, not a person; local chain has no external anchor. '
        +'AES-CBC encryption is integrity checked through the record hash and optional RSA-PSS signature. '
        +'Paillier input bounds are validated locally, not proved cryptographically. '
        +'ElGamal uses a runtime prime and base 2 without a proof that the base generates the full group. '
        +'Shamir reconstructs the Paillier decryption secret locally; it is not distributed partial decryption. '
        +'TCP is loopback-only and carries role PINs without transport encryption. '
        +'Unsupported: automatic prose-to-application conversion, external chain anchoring, cryptographic range proofs, remote authenticated transport, UDP, multipart message reassembly.\n'
        +('Separate programs: start server first with python -B '+launchers[0].name+'; then run client with python -B '+launchers[1].name+'. Keep the shared '+output.name+' file beside both.\n' if launchers else ''),encoding='utf-8')
    return output,report
