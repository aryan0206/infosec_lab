"""Schema-driven standalone application engine. CONFIG is injected by the builder."""
import getpass
import hashlib
import hmac
import json
import math
import secrets
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as asympad, rsa, dsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key, load_pem_public_key

CONFIG = {}
OPERATIONS = ('submit', 'view', 'verify', 'search', 'approve', 'decrypt', 'aggregate', 'keys', 'rsa_product', 'hex_dump', 'serve', 'send')
MAX_FRAME = 1_000_000

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    temp.replace(path)

def load(path, default):
    return json.loads(Path(path).read_text(encoding='utf-8')) if Path(path).exists() else default

def validate_value(field, value):
    kind = field['type']
    if value is None and not field.get('required', True): return None
    if kind == 'text':
        if not isinstance(value, str): raise ValueError(field['name'] + ' must be text')
        if field.get('required', True) and not value: raise ValueError(field['name'] + ' is required')
        if len(value) > field.get('max_length', 1000): raise ValueError(field['name'] + ' is too long')
        if len(value) < field.get('min_length', 0): raise ValueError(field['name'] + ' is too short')
        if field.get('choices') and value not in field['choices']: raise ValueError(field['name'] + ' is not an allowed choice')
    elif kind == 'integer':
        if type(value) is not int: raise ValueError(field['name'] + ' must be an integer')
        if not field.get('min', -10**12) <= value <= field.get('max', 10**12): raise ValueError(field['name'] + ' outside allowed range')
    elif kind == 'boolean':
        if type(value) is not bool: raise ValueError(field['name'] + ' must be true or false')
    else: raise ValueError('Unsupported field type')
    return value

def aes_encrypt(data, key, mode):
    if len(key) not in (16,24,32):raise ValueError('Invalid AES key length')
    if mode == 'GCM':
        nonce = secrets.token_bytes(12)
        return {'mode': mode, 'nonce': nonce.hex(), 'ciphertext': AESGCM(key).encrypt(nonce, data, None).hex()}
    if mode != 'CBC':raise ValueError('Unsupported AES mode')
    iv = secrets.token_bytes(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return {'mode': mode, 'iv': iv.hex(), 'ciphertext': (encryptor.update(padded) + encryptor.finalize()).hex()}

def aes_decrypt(blob, key):
    if len(key) not in (16,24,32):raise ValueError('Invalid AES key length')
    if blob['mode'] == 'GCM': return AESGCM(key).decrypt(bytes.fromhex(blob['nonce']), bytes.fromhex(blob['ciphertext']), None)
    if blob['mode']!='CBC':raise ValueError('Unsupported AES mode')
    decryptor = Cipher(algorithms.AES(key), modes.CBC(bytes.fromhex(blob['iv']))).decryptor()
    padded = decryptor.update(bytes.fromhex(blob['ciphertext'])) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def paillier_keys(bits):
    numbers = rsa.generate_private_key(public_exponent=65537, key_size=bits).private_numbers()
    p, q = numbers.p, numbers.q
    n = p*q
    lam = math.lcm(p-1, q-1)
    return {'n': n, 'lambda': lam, 'mu': pow(lam, -1, n)}

def paillier_encrypt(value, key):
    n = key['n']
    if not 0 <= value < n: raise ValueError('Paillier value exceeds modulus')
    while True:
        r = secrets.randbelow(n-1)+1
        if math.gcd(r,n)==1: break
    return pow(n+1,value,n*n)*pow(r,n,n*n)%(n*n)

def paillier_decrypt(cipher, key):
    n=key['n']
    if type(cipher) is not int or not 1<=cipher<n*n or math.gcd(cipher,n)!=1:raise ValueError('Invalid Paillier ciphertext')
    return (((pow(cipher,key['lambda'],n*n)-1)//n)*key['mu'])%n

def elgamal_keys(bits):
    prime=rsa.generate_private_key(public_exponent=65537,key_size=bits*2).private_numbers().p
    generator=2
    secret=secrets.randbelow(prime-3)+2
    return {'p':str(prime),'g':generator,'y':str(pow(generator,secret,prime)),'x':str(secret)}

def elgamal_sign(digest,key):
    p=int(key['p']);x=int(key['x']);g=int(key['g'])
    h=int.from_bytes(digest,'big')%(p-1)
    while True:
        k=secrets.randbelow(p-2)+1
        if math.gcd(k,p-1)==1:break
    r=pow(g,k,p);s=((h-x*r)*pow(k,-1,p-1))%(p-1)
    return {'r':str(r),'s':str(s)}

def elgamal_verify(digest,signature,key):
    try:
        p=int(key['p']);g=int(key['g']);y=int(key['y']);r=int(signature['r']);s=int(signature['s'])
        return 1<=r<p and 0<=s<p-1 and pow(g,int.from_bytes(digest,'big')%(p-1),p)==pow(y,r,p)*pow(r,s,p)%p
    except (KeyError,TypeError,ValueError):return False

def schnorr_keys(bits):
    parameters=dsa.generate_parameters(key_size=bits).parameter_numbers()
    p,q,g=parameters.p,parameters.q,parameters.g
    secret=secrets.randbelow(q-1)+1
    return {'p':str(p),'q':str(q),'g':str(g),'y':str(pow(g,secret,p)),'x':str(secret)}

def schnorr_challenge(commitment,digest,q):
    material=b'IS-LAB-SCHNORR-v1'+len(digest).to_bytes(4,'big')+digest+commitment.to_bytes((commitment.bit_length()+7)//8,'big')
    return int.from_bytes(hashlib.sha256(material).digest(),'big')%q

def schnorr_sign(digest,key):
    p,q,g,x=(int(key[k]) for k in ('p','q','g','x'))
    nonce=secrets.randbelow(q-1)+1
    commitment=pow(g,nonce,p)
    challenge=schnorr_challenge(commitment,digest,q)
    return {'r':str(commitment),'s':str((nonce+challenge*x)%q)}

def schnorr_verify(digest,signature,key):
    try:
        p,q,g,y=(int(key[k]) for k in ('p','q','g','y'))
        commitment=int(signature['r']);response=int(signature['s'])
        if not 1<commitment<p or not 0<=response<q:return False
        if pow(commitment,q,p)!=1 or pow(y,q,p)!=1:return False
        challenge=schnorr_challenge(commitment,digest,q)
        return pow(g,response,p)==commitment*pow(y,challenge,p)%p
    except (KeyError,TypeError,ValueError):return False

def shamir_split(secret,threshold,count):
    if type(secret) is not int or secret<0 or not 2<=threshold<=count<=8:raise ValueError('Invalid sharing parameters')
    prime=rsa.generate_private_key(public_exponent=65537,key_size=2*(secret.bit_length()+64)).private_numbers().p
    coefficients=[secret]+[secrets.randbelow(prime) for _ in range(threshold-1)]
    return {'prime':str(prime),'threshold':threshold,'shares':[[i,str(sum(c*pow(i,j,prime) for j,c in enumerate(coefficients))%prime)] for i in range(1,count+1)]}

def shamir_reconstruct(shares,prime,threshold):
    if len(shares)<threshold:raise ValueError('Insufficient distinct Shamir shares')
    if len({int(x) for x,_ in shares})!=len(shares):raise ValueError('Duplicate Shamir share')
    result=0
    for x,y in shares:
        x=int(x);y=int(y);numerator=denominator=1
        for other,_ in shares:
            other=int(other)
            if other!=x:numerator=numerator*(-other)%prime;denominator=denominator*(x-other)%prime
        result=(result+y*numerator*pow(denominator,-1,prime))%prime
    return result

def frame_bytes(value):
    payload=canonical(value)
    if not 0<len(payload)<=MAX_FRAME:raise ValueError('Frame length out of range')
    return str(len(payload)).encode('ascii')+b'\n'+payload

def read_frame(connection):
    connection.settimeout(3)
    try:
        header=bytearray()
        while not header.endswith(b'\n'):
            byte=connection.recv(1)
            if not byte or len(header)>=20:raise ValueError('Malformed or incomplete frame header')
            header.extend(byte)
        if not header[:-1].isdigit():raise ValueError('Nondecimal frame length')
        length=int(header[:-1])
        if not 0<length<=MAX_FRAME:raise ValueError('Frame length out of range')
        payload=bytearray()
        while len(payload)<length:
            part=connection.recv(length-len(payload))
            if not part:raise ValueError('Incomplete frame body')
            payload.extend(part)
        try:return json.loads(payload.decode('utf-8'))
        except (UnicodeError,json.JSONDecodeError) as exc:raise ValueError('Malformed JSON frame') from exc
    except socket.timeout as exc:raise ValueError('Timed out during frame read') from exc

def hex_dump(data):
    if isinstance(data,str):data=data.encode('utf-8')
    elif not isinstance(data,bytes):data=canonical(data)
    return '\n'.join(f'{offset:08x}  '+ ' '.join(f'{byte:02x}' for byte in data[offset:offset+16]).ljust(47)+
      '  '+''.join(chr(byte) if 32<=byte<127 else '.' for byte in data[offset:offset+16]) for offset in range(0,len(data),16))

class Application:
    def __init__(self, directory, config=None):
        self.config=config or CONFIG
        self.directory=Path(directory)
        self.directory.mkdir(parents=True,exist_ok=True)
        self._authenticated=set()
        self.records_path=self.directory/'records.json'
        self.keys_path=self.directory/'keys.json'
        self.private_path=self.directory/'signature_private.pem'
        self.signature_public_path=self.directory/'signature_public.pem'
        self.wrap_path=self.directory/'wrap_private.pem'
        self.wrap_public_path=self.directory/'wrap_public.pem'
        self.textbook_path=self.directory/'textbook_private.pem'
        self.elgamal_path=self.directory/'elgamal_private.json'
        self.schnorr_path=self.directory/'schnorr_private.json'
        self.shares_path=self.directory/'shares.json'
        self.accounts_path=self.directory/'accounts.json'
        if self.records_path.exists() and not self.keys_path.exists(): raise ValueError('Key state missing for existing records')
        if not self.keys_path.exists():
            keys={'aes':secrets.token_bytes(self.config['aes_bits']//8).hex() if self.config['encryption']!='none' and not self.config.get('key_wrapping') else None,
                  'search':secrets.token_bytes(32).hex(), 'paillier':None,'elgamal':None,'schnorr':None}
            if self.config['aggregate_field']:
                paillier=paillier_keys(self.config['paillier_bits'])
                if self.config.get('shamir'):
                    save(self.shares_path,shamir_split(paillier['lambda'],self.config['shamir']['threshold'],self.config['shamir']['shares']))
                    del paillier['lambda']
                keys['paillier']={k:str(v) for k,v in paillier.items()}
            if self.config['signature']=='elgamal':
                elgamal=elgamal_keys(self.config.get('elgamal_bits',512))
                save(self.elgamal_path,{'x':elgamal.pop('x')})
                keys['elgamal']=elgamal
            if self.config['signature']=='schnorr':
                schnorr=schnorr_keys(self.config.get('schnorr_bits',2048))
                save(self.schnorr_path,{'x':schnorr.pop('x')})
                keys['schnorr']=schnorr
            save(self.keys_path,keys)
            if self.config['signature']=='rsa_pss':
                private=rsa.generate_private_key(public_exponent=65537,key_size=self.config['rsa_bits'])
                self.private_path.write_bytes(private.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
                self.signature_public_path.write_bytes(private.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
            for enabled,path in ((self.config.get('key_wrapping'),self.wrap_path),(self.config.get('textbook_rsa'),self.textbook_path)):
                if enabled:
                    private=rsa.generate_private_key(public_exponent=65537,key_size=self.config['rsa_bits'])
                    path.write_bytes(private.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
                    if path==self.wrap_path:self.wrap_public_path.write_bytes(private.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
        self.keys=load(self.keys_path,{})
        if self.config['signature']=='rsa_pss':
            if not self.private_path.exists() or not self.signature_public_path.exists(): raise ValueError('Signing key missing')
            self.private=load_pem_private_key(self.private_path.read_bytes(),password=None)
            self.signature_public=load_pem_public_key(self.signature_public_path.read_bytes())
        else: self.private=None
        if self.config['signature']=='elgamal' and not self.elgamal_path.exists():raise ValueError('ElGamal private key missing')
        self.elgamal_private={**self.keys['elgamal'],**load(self.elgamal_path,{})} if self.config['signature']=='elgamal' else None
        if self.config['signature']=='schnorr' and not self.schnorr_path.exists():raise ValueError('Schnorr private key missing')
        self.schnorr_private={**self.keys['schnorr'],**load(self.schnorr_path,{})} if self.config['signature']=='schnorr' else None
        if self.config.get('key_wrapping') and (not self.wrap_path.exists() or not self.wrap_public_path.exists()):raise ValueError('RSA wrapping key missing')
        self.wrap_private=load_pem_private_key(self.wrap_path.read_bytes(),password=None) if self.config.get('key_wrapping') else None
        self.wrap_public=load_pem_public_key(self.wrap_public_path.read_bytes()) if self.config.get('key_wrapping') else None
        if self.config.get('textbook_rsa') and not self.textbook_path.exists():raise ValueError('Textbook RSA key missing')
        self.textbook_private=load_pem_private_key(self.textbook_path.read_bytes(),password=None) if self.config.get('textbook_rsa') else None
        if self.config.get('shamir') and not self.shares_path.exists():raise ValueError('Shamir shares missing')
        self.paillier={k:int(v) for k,v in self.keys['paillier'].items()} if self.keys['paillier'] else None

    def configure_pin(self,role,pin):
        if role not in self.config['roles'] or not self.config['roles'][role]['auth']: raise ValueError('Role does not require PIN')
        if len(pin)<4: raise ValueError('PIN must contain at least four characters')
        accounts=load(self.accounts_path,{})
        if role in accounts: raise ValueError('PIN already configured')
        salt=secrets.token_bytes(16)
        accounts[role]={'salt':salt.hex(),'digest':hashlib.pbkdf2_hmac('sha256',pin.encode(),salt,200000).hex()}
        save(self.accounts_path,accounts)

    def authenticate(self,role,pin=None):
        if role not in self.config['roles']: raise ValueError('Unknown role')
        if self.config['roles'][role]['auth']:
            account=load(self.accounts_path,{}).get(role)
            if not account: raise ValueError('Role PIN must be configured first')
            expected=bytes.fromhex(account['digest'])
            actual=hashlib.pbkdf2_hmac('sha256',(pin or '').encode(),bytes.fromhex(account['salt']),200000)
            if not hmac.compare_digest(expected,actual): raise PermissionError('Authentication failed')
        self._authenticated.add(role)
        return True

    def allowed(self,role,operation,record=None):
        policy=self.config['roles'].get(role)
        if not policy or operation not in policy['operations']: raise PermissionError(role+' cannot '+operation)
        if policy['auth'] and role not in self._authenticated:raise PermissionError('Authenticate role first')
        if record is not None:
            if policy['access']=='own' and record['owner']!=role: raise PermissionError('Record owner restriction')
            condition=policy.get('condition')
            if condition and record['fields'].get(condition['field'])!=condition['equals']: raise PermissionError('Record condition restriction')

    def records(self):
        rows=load(self.records_path,[])
        previous='0'*64
        ids=set(); nonces=set()
        for i,row in enumerate(rows,1):
            if row['prev_hash']!=previous: raise ValueError('Broken chain link at record '+str(i))
            body={k:v for k,v in row.items() if k!='chain_hash'}
            if row['chain_hash']!=hashlib.sha256(canonical(body)).hexdigest(): raise ValueError('Broken chain hash at record '+str(i))
            if row['id'] in ids or row['nonce'] in nonces: raise ValueError('Replay or duplicate at record '+str(i))
            ids.add(row['id']); nonces.add(row['nonce']); previous=row['chain_hash']
            if not self.verify_signature(row): raise ValueError('Invalid record signature at record '+str(i))
        return rows

    def verify_signature(self,row):
        digest=bytes.fromhex(row['digest'])
        body={k:v for k,v in row.items() if k not in ('digest','signature','prev_hash','chain_hash','approval')}
        if hashlib.new(self.config['hash'],canonical(body)).digest()!=digest:return False
        if self.private:
            try:
                self.signature_public.verify(bytes.fromhex(row['signature']),digest,asympad.PSS(mgf=asympad.MGF1(hashes.SHA256()),salt_length=asympad.PSS.MAX_LENGTH),hashes.SHA256())
            except (InvalidSignature,ValueError):return False
        elif self.config['signature']=='elgamal' and not elgamal_verify(digest,row['signature'],self.keys['elgamal']):return False
        elif self.config['signature']=='schnorr' and not schnorr_verify(digest,row['signature'],self.keys['schnorr']):return False
        return True

    def submit(self,role,values,record_id=None,timestamp=None,nonce=None):
        self.allowed(role,'submit')
        rows=self.records()
        record_id=record_id or secrets.token_hex(8)
        if any(row['id']==record_id for row in rows):raise ValueError('Duplicate record ID')
        nonce=nonce or secrets.token_hex(16)
        if any(row['nonce']==nonce for row in rows):raise ValueError('Replay nonce')
        timestamp=timestamp or datetime.now(timezone.utc).isoformat()
        self.check_freshness(timestamp)
        if set(values)-{f['name'] for f in self.config['fields']}:raise ValueError('Unknown field')
        fields={}; index={}
        record_key=secrets.token_bytes(self.config['aes_bits']//8) if self.config.get('key_wrapping') else None
        for field in self.config['fields']:
            name=field['name']; value=validate_value(field,values.get(name))
            if value is None:continue
            if field.get('encrypted'):
                key=record_key or bytes.fromhex(self.keys['aes'])
                # Persistent local key permits restart recovery.
                fields[name]=aes_encrypt(canonical(value),key,self.config['encryption'])
            elif name==self.config['aggregate_field']:
                fields[name]={'paillier':str(paillier_encrypt(value,self.paillier))}
            else:fields[name]=value
            if field.get('searchable'):
                token=hmac.new(bytes.fromhex(self.keys['search']),canonical([name,value]),self.config['hmac_hash']).hexdigest()
                index[name]=token
        row={'id':record_id,'owner':role,'fields':fields,'index':index,'timestamp':timestamp,'nonce':nonce}
        if record_key:
            oaep=asympad.OAEP(mgf=asympad.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
            row['wrapped_key']=self.wrap_public.encrypt(record_key,oaep).hex()
        row['digest']=hashlib.new(self.config['hash'],canonical(row)).hexdigest()
        row['signature']=(self.private.sign(bytes.fromhex(row['digest']),asympad.PSS(mgf=asympad.MGF1(hashes.SHA256()),salt_length=asympad.PSS.MAX_LENGTH),hashes.SHA256()).hex() if self.private else
                          elgamal_sign(bytes.fromhex(row['digest']),self.elgamal_private) if self.config['signature']=='elgamal' else
                          schnorr_sign(bytes.fromhex(row['digest']),self.schnorr_private) if self.config['signature']=='schnorr' else None)
        row['prev_hash']=rows[-1]['chain_hash'] if rows else '0'*64
        row['chain_hash']=hashlib.sha256(canonical({k:v for k,v in row.items() if k!='chain_hash'})).hexdigest()
        rows.append(row);save(self.records_path,rows)
        return record_id

    def select(self,role,record_id,operation='view'):
        row=next((r for r in self.records() if r['id']==record_id),None)
        if row is None:raise ValueError('Record not found')
        self.allowed(role,operation,row)
        if operation in ('verify','decrypt','aggregate','hex_dump'):self.check_freshness(row['timestamp'])
        return row

    def check_freshness(self,timestamp):
        try:when=datetime.fromisoformat(timestamp)
        except (TypeError,ValueError) as exc:raise ValueError('Invalid timestamp') from exc
        if when.tzinfo is None:raise ValueError('Timestamp must have timezone')
        window=self.config.get('freshness_seconds',0)
        if window and abs((datetime.now(timezone.utc)-when).total_seconds())>window:raise ValueError('Stale or future timestamp')

    def view(self,role,record_id):
        row=self.select(role,record_id)
        allowed_fields=self.config['roles'][role].get('view_fields') or [f['name'] for f in self.config['fields']]
        return {'id':row['id'],'owner':row['owner'],'fields':{k:v for k,v in row['fields'].items() if k in allowed_fields},'approval':row.get('approval')}

    def decrypt(self,role,record_id,field_name):
        row=self.select(role,record_id,'decrypt')
        if field_name not in self.config['roles'][role].get('decrypt_fields',[]):raise PermissionError('Field decrypt restriction')
        blob=row['fields'][field_name]
        if not isinstance(blob,dict) or 'ciphertext' not in blob:raise ValueError('Field is not AES encrypted')
        if self.wrap_private:
            oaep=asympad.OAEP(mgf=asympad.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
            key=self.wrap_private.decrypt(bytes.fromhex(row['wrapped_key']),oaep)
        else:key=bytes.fromhex(self.keys['aes'])
        return json.loads(aes_decrypt(blob,key).decode())

    def search(self,role,field_name,value):
        self.allowed(role,'search')
        field=next((f for f in self.config['fields'] if f['name']==field_name),None)
        if not field or not field.get('searchable'):raise ValueError('Field is not searchable')
        value=validate_value(field,value)
        token=hmac.new(bytes.fromhex(self.keys['search']),canonical([field_name,value]),self.config['hmac_hash']).hexdigest()
        result=[]
        for row in self.records():
            if hmac.compare_digest(row['index'].get(field_name,''),token):
                try:self.allowed(role,'search',row);result.append(row['id'])
                except PermissionError:pass
        return result

    def verify(self,role,record_id):
        self.select(role,record_id,'verify')
        return True

    def aggregate(self,role,ids,weights=None,share_indexes=None):
        self.allowed(role,'aggregate')
        if not self.paillier:raise ValueError('Aggregation not configured')
        if len(ids)!=len(set(ids)) or not ids:raise ValueError('Duplicate or empty record IDs')
        weights=weights or [1]*len(ids)
        if len(weights)!=len(ids) or any(type(w) is not int or w<0 for w in weights):raise ValueError('Invalid weights')
        field=self.config['aggregate_field']; limit=next(f['max'] for f in self.config['fields'] if f['name']==field)
        if sum(weights)*limit>=self.paillier['n']:raise ValueError('Aggregate may wrap modulus')
        product=1; modulus=self.paillier['n']**2
        for record_id,weight in zip(ids,weights):
            row=self.select(role,record_id,'aggregate')
            product=product*pow(int(row['fields'][field]['paillier']),weight,modulus)%modulus
        private=dict(self.paillier)
        if self.config.get('shamir'):
            state=load(self.shares_path,{})
            share_indexes=share_indexes or []
            if len(share_indexes)<state['threshold']:raise ValueError('Insufficient distinct Shamir shares')
            chosen=[item for item in state['shares'] if item[0] in share_indexes]
            if len(chosen)!=len(share_indexes):raise ValueError('Unknown or duplicate Shamir share')
            private['lambda']=shamir_reconstruct(chosen,int(state['prime']),state['threshold'])
        total=paillier_decrypt(product,private)
        weighted=weights!=[1]*len(ids)
        return {'sum':total,'count':len(ids),'mean':None if weighted else total/len(ids),'weighted':weighted}

    def approve(self,role,record_id,decision):
        row=self.select(role,record_id,'approve')
        if decision not in ('approved','rejected'):raise ValueError('Invalid decision')
        rows=self.records()
        for item in rows:
            if item['id']==record_id:
                item['approval']={'by':role,'decision':decision}
                item['chain_hash']=hashlib.sha256(canonical({k:v for k,v in item.items() if k!='chain_hash'})).hexdigest()
                break
        # Rechain subsequent entries after a legitimate decision.
        for i in range(1,len(rows)):
            rows[i]['prev_hash']=rows[i-1]['chain_hash']
            rows[i]['chain_hash']=hashlib.sha256(canonical({k:v for k,v in rows[i].items() if k!='chain_hash'})).hexdigest()
        save(self.records_path,rows)

    def rsa_product(self,role,left,right):
        self.allowed(role,'rsa_product')
        if not self.textbook_private:raise ValueError('Textbook RSA component disabled')
        numbers=self.textbook_private.private_numbers();public=numbers.public_numbers
        n=public.n;e=public.e;d=numbers.d
        if type(left) is not int or type(right) is not int or not 1<=left<n or not 1<=right<n:
            raise ValueError('Inputs must be integers in 1..n-1')
        ciphertexts=[pow(left,e,n),pow(right,e,n)]
        combined=ciphertexts[0]*ciphertexts[1]%n
        result=pow(combined,d,n)
        return {'ciphertexts':ciphertexts,'combined':combined,'decrypted':result,
                'expected_mod_n':left*right%n,'verified':result==left*right%n}

    def hex_dump(self,role,record_id,field_name):
        self.select(role,record_id,'hex_dump')
        if field_name not in self.config['roles'][role].get('decrypt_fields',[]):raise PermissionError('Field dump restriction')
        return hex_dump(self.decrypt(role,record_id,field_name))

    def serve_once(self,role,ready=None):
        self.allowed(role,'serve')
        port=self.config.get('tcp_port')
        if port is None:raise ValueError('TCP disabled')
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            server.bind((self.config.get('tcp_host','127.0.0.1'),port));server.listen(1);server.settimeout(10)
            if ready:ready.set()
            with server.accept()[0] as connection:
                try:
                    answer=self.handle_packet(read_frame(connection))
                except (ValueError,PermissionError,KeyError,TypeError,OSError) as exc:answer={'ok':False,'error':str(exc)}
                connection.sendall(frame_bytes(answer))
                return answer

    def handle_packet(self,packet):
        if not isinstance(packet,dict) or set(packet)!={'role','pin','values','nonce','timestamp'}:raise ValueError('Malformed submission packet')
        if not isinstance(packet['values'],dict):raise ValueError('Malformed field values')
        self.authenticate(packet['role'],packet['pin'])
        record_id=self.submit(packet['role'],packet['values'],nonce=packet['nonce'],timestamp=packet['timestamp'])
        return {'ok':True,'record_id':record_id}

    def serve_forever(self,role,ready=None,stop_event=None):
        self.allowed(role,'serve')
        if self.config.get('architecture')!='tcp_client_server':raise ValueError('Separate TCP architecture not selected')
        lock=threading.Lock();stop_event=stop_event or threading.Event()
        def worker(connection):
            with connection:
                try:
                    packet=read_frame(connection)
                    with lock:
                        app=Application(self.directory,self.config)
                        answer=app.handle_packet(packet)
                except (ValueError,PermissionError,KeyError,TypeError,OSError) as exc:answer={'ok':False,'error':str(exc)}
                try:connection.sendall(frame_bytes(answer))
                except OSError:pass
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server,ThreadPoolExecutor(max_workers=8) as pool:
            server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            server.bind((self.config.get('tcp_host','127.0.0.1'),self.config['tcp_port']))
            server.listen(16);server.settimeout(.2)
            if ready:ready.set()
            while not stop_event.is_set():
                try:connection,_=server.accept()
                except socket.timeout:continue
                pool.submit(worker,connection)

    def send(self,role,values,pin=None,nonce=None,timestamp=None):
        self.allowed(role,'send')
        packet={'role':role,'pin':pin,'values':values,'nonce':nonce or secrets.token_hex(16),
                'timestamp':timestamp or datetime.now(timezone.utc).isoformat()}
        with socket.create_connection((self.config.get('tcp_host','127.0.0.1'),self.config['tcp_port']),timeout=3) as connection:
            connection.sendall(frame_bytes(packet))
            response=read_frame(connection)
        if not isinstance(response,dict) or not response.get('ok'):raise ValueError(response.get('error','Invalid server response'))
        return response['record_id']

def server_main():
    if CONFIG.get('architecture')!='tcp_client_server':raise ValueError('TCP client/server architecture not selected')
    app=Application(Path(__file__).resolve().parent/'demo_data'/Path(__file__).stem)
    roles=[name for name,policy in CONFIG['roles'].items() if 'serve' in policy['operations']]
    role=roles[0] if len(roles)==1 else input('Server role ('+', '.join(roles)+'): ').strip()
    app.authenticate(role,getpass.getpass('Server role PIN: ') if CONFIG['roles'][role]['auth'] else None)
    print('Server listening on',CONFIG['tcp_host'],CONFIG['tcp_port'],'(Ctrl+C to stop)')
    try:app.serve_forever(role)
    except KeyboardInterrupt:print('Server stopped')

def client_main():
    if CONFIG.get('architecture')!='tcp_client_server':raise ValueError('TCP client/server architecture not selected')
    roles=[name for name,policy in CONFIG['roles'].items() if 'send' in policy['operations']]
    role=roles[0] if len(roles)==1 else input('Client role ('+', '.join(roles)+'): ').strip()
    if role not in roles:raise ValueError('Unknown client role')
    pin=getpass.getpass('Client role PIN: ') if CONFIG['roles'][role]['auth'] else None
    values={field['name']:prompt_value(field) for field in CONFIG['fields']}
    packet={'role':role,'pin':pin,'values':values,'nonce':secrets.token_hex(16),'timestamp':datetime.now(timezone.utc).isoformat()}
    with socket.create_connection((CONFIG['tcp_host'],CONFIG['tcp_port']),timeout=3) as connection:
        connection.sendall(frame_bytes(packet))
        answer=read_frame(connection)
    print('Server response:',answer)

def prompt_value(field):
    raw=input(field.get('label',field['name'])+': ')
    if not raw and not field.get('required',True):return None
    if field['type']=='integer':return int(raw)
    if field['type']=='boolean':return raw.lower() in ('yes','y','true','1')
    return raw

def menu():
    app=Application(Path(__file__).resolve().parent/'demo_data'/Path(__file__).stem)
    print('Application:',CONFIG['title'])
    while True:
        role=input('Role ('+', '.join(CONFIG['roles'])+'; 0 exit): ').strip()
        if role=='0':return
        if role not in CONFIG['roles']:print('Unknown role');continue
        try:
            if CONFIG['roles'][role]['auth'] and role not in load(app.accounts_path,{}):
                app.configure_pin(role,getpass.getpass('Set new role PIN (>=4 chars): '))
            app.authenticate(role,getpass.getpass('Role PIN: ') if CONFIG['roles'][role]['auth'] else None)
            operations=CONFIG['roles'][role]['operations']
            while True:
                print('Operations:',', '.join(operations),'| back')
                op=input('Action: ').strip().lower()
                if op=='back':break
                if op not in operations:print('Not permitted');continue
                if op=='submit':print('Record ID:',app.submit(role,{f['name']:prompt_value(f) for f in CONFIG['fields']}))
                elif op=='view':print(json.dumps(app.view(role,input('Record ID: ')),indent=2))
                elif op=='verify':print('Verified:',app.verify(role,input('Record ID: ')))
                elif op=='search':
                    name=input('Search field: ');field=next(f for f in CONFIG['fields'] if f['name']==name)
                    print('Matches:',app.search(role,name,prompt_value(field)))
                elif op=='decrypt':print('Plaintext:',app.decrypt(role,input('Record ID: '),input('Field: ')))
                elif op=='aggregate':
                    ids=[v.strip() for v in input('Record IDs (comma separated): ').split(',')]
                    weights_raw=input('Weights (comma separated, Enter for sum): ').strip()
                    weights=[int(v.strip()) for v in weights_raw.split(',')] if weights_raw else None
                    shares_raw=input('Shamir share numbers (comma separated, Enter if disabled): ').strip() if CONFIG.get('shamir') else ''
                    shares=[int(v.strip()) for v in shares_raw.split(',')] if shares_raw else None
                    print(app.aggregate(role,ids,weights,shares))
                elif op=='approve':app.approve(role,input('Record ID: '),input('Decision (approved/rejected): '))
                elif op=='keys':print('Key files:',app.keys_path,app.private_path if app.private else '')
                elif op=='rsa_product':print(app.rsa_product(role,int(input('First integer: ')),int(input('Second integer: '))))
                elif op=='hex_dump':print(app.hex_dump(role,input('Record ID: '),input('Field: ')))
                elif op=='serve':print('Received:',app.serve_once(role))
                elif op=='send':
                    values={f['name']:prompt_value(f) for f in CONFIG['fields']}
                    pin=getpass.getpass('Sender role PIN for loopback receiver: ') if CONFIG['roles'][role]['auth'] else None
                    print('Sent record ID:',app.send(role,values,pin))
        except (ValueError,KeyError,PermissionError,TypeError,OSError) as exc:print('Operation failed:',exc)

def self_test():
    with tempfile.TemporaryDirectory() as directory:
        app=Application(directory)
        submitter=next((r for r,p in CONFIG['roles'].items() if 'submit' in p['operations']),None)
        if submitter:
            if CONFIG['roles'][submitter]['auth']:
                app.configure_pin(submitter,'selftest-pin')
                app.authenticate(submitter,'selftest-pin')
            values={f['name']:('x' if f['type']=='text' else 1 if f['type']=='integer' else True) for f in CONFIG['fields']}
            for f in CONFIG['fields']:
                if f.get('choices'):values[f['name']]=f['choices'][0]
                if f['type']=='text' and f.get('min_length',0)>1:values[f['name']]='x'*f['min_length']
                if f['type']=='integer':values[f['name']]=max(0,f.get('min',0))
            rid=app.submit(submitter,values)
            assert app.records()[0]['id']==rid
            assert Application(directory).records()[0]['id']==rid
    print('SELF-TEST PASSED')

if __name__=='__main__':
    if '--self-test' in sys.argv:self_test()
    else:menu()
