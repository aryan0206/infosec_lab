"""Question D educational mechanisms; not a real election or true threshold/SSE protocol."""
import sys,json,hmac,secrets
from pathlib import Path
from datetime import datetime,timezone
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import *
from store import *

def utc(text):return datetime.fromisoformat(text.replace('Z','+00:00')).astimezone(timezone.utc)
class VotingApp:
    def __init__(self,directory,clock=None):
        self.dir=Path(directory);self.dir.mkdir(parents=True,exist_ok=True)
        self.clock=clock or (lambda:datetime.now(timezone.utc))
        self.path=self.dir/'ballots.json';self.config=self.dir/'election.json'
        self.index_key_path=self.dir/'index.key'
        self.aes,self.rsa,self.pub,self.priv=demo_keys(self.dir,rsa_bits=4096)
        self.pub=paillier_public(self.pub);self.priv=paillier_private(self.priv)
        if not self.index_key_path.exists():self.index_key_path.write_bytes(secrets.token_bytes(32))
    def setup(self,start,end,candidates):
        if utc(start)>=utc(end) or candidates<2:raise ValueError('Invalid period or candidate count')
        write_json(self.config,{'start':start,'end':end,'candidates':candidates})
    def settings(self):
        x=read_json(self.config,{})
        if not x:raise ValueError('Set election period first')
        return x
    def rows(self):
        rows=read_json(self.path,[])
        if not isinstance(rows,list):raise ValueError('Malformed ballots file')
        return rows
    def token(self,kind,value):return hmac.new(self.index_key_path.read_bytes(),f'{kind}:{value}'.encode(),hashlib.sha256).hexdigest()
    def cast(self,ballot_id,candidate,constituency,timestamp=None):
        conf=self.settings();now=self.clock() if timestamp is None else utc(timestamp)
        if not utc(conf['start'])<=now<=utc(conf['end']):raise ValueError('Timestamp outside voting period')
        if not 1<=candidate<=conf['candidates'] or not constituency.strip() or not ballot_id.strip():raise ValueError('Invalid ballot')
        rows=self.rows()
        if any(r['ballot_id']==ballot_id for r in rows):raise ValueError('Duplicate ballot ID')
        ballot={'candidate_id':candidate,'constituency_id':constituency}
        raw=canonical(ballot);digest=hashlib.sha512(raw).digest();key=secrets.token_bytes(32)
        voter_public,voter_private=elgamal_keypair()
        item={'format_version':2,'ballot_id':ballot_id,'timestamp':now.isoformat(),'constituency_token':self.token('constituency',constituency.casefold()),'day_token':self.token('day',now.date().isoformat()),'sha512':digest.hex(),'aes_cbc':cbc_encrypt_record(raw,key,2),'wrapped_aes_key':rsa_wrap_record(key,self.rsa.public_key(),2),'elgamal_public':voter_public,'elgamal_signature':elgamal_sign_digest(digest,voter_public,voter_private),'encrypted_candidate_id':encode_integer(paillier_encrypt(candidate,self.pub),2),'encrypted_indicators':[encode_integer(paillier_encrypt(int(candidate==i),self.pub),2) for i in range(1,conf['candidates']+1)]}
        # This extra RSA signature covers all metadata and ciphertext, including Paillier values.
        item['server_record_signature']=rsa_sign_record(canonical(item),self.rsa,2)
        rows.append(item);write_json(self.path,rows);return item
    def verify(self,item):
        try:
            conf=self.settings();version=format_version(item);sig=item['server_record_signature']
            if not rsa_verify_record(canonical({k:v for k,v in item.items() if k!='server_record_signature'}),sig,self.rsa.public_key(),version):return False
            if version==2:
                decode_integer(item['encrypted_candidate_id'],2)
                for value in item['encrypted_indicators']:decode_integer(value,2)
                decode_bytes(item['constituency_token'],2)
                decode_bytes(item['day_token'],2)
            stamp=utc(item['timestamp'])
            if not utc(conf['start'])<=stamp<=utc(conf['end']):return False
            if self.token('day',stamp.date().isoformat())!=item['day_token']:return False
            digest=decode_bytes(item['sha512'],2) if version==2 else bytes.fromhex(item['sha512'])
            if not elgamal_verify_digest(digest,item['elgamal_signature'],item['elgamal_public']):return False
            key=rsa_unwrap_record(item['wrapped_aes_key'],self.rsa,version)
            ballot=json.loads(cbc_decrypt_record(item['aes_cbc'],key,version))
            return hashlib.sha512(canonical(ballot)).digest()==digest and self.token('constituency',ballot['constituency_id'].casefold())==item['constituency_token'] and len(item['encrypted_indicators'])==conf['candidates']
        except (KeyError,ValueError,TypeError,InvalidTag):return False
    def search(self,constituency=None,start=None,end=None):
        token=self.token('constituency',constituency.casefold()) if constituency else None
        matches=[]
        for r in self.rows():
            if token and r['constituency_token']!=token:continue
            if start and utc(r['timestamp'])<utc(start):continue
            if end and utc(r['timestamp'])>utc(end):continue
            matches.append({'ballot_id':r['ballot_id'],'timestamp':r['timestamp'],'verified':self.verify(r)})
        return matches
    def tally(self,authority_a,authority_b):
        current=self.clock()
        if current.tzinfo is None:raise ValueError('Tally clock must include a timezone')
        if current.astimezone(timezone.utc)<utc(self.settings()['end']):
            raise ValueError('Tally blocked until the election closes')
        if authority_a!='A' or authority_b!='B':raise ValueError('Two demo authority approvals A and B required')
        rows=self.rows();conf=self.settings()
        if not rows:raise ValueError('No ballots')
        if any(not self.verify(r) for r in rows):raise ValueError('Tampering detected; tally blocked')
        if len(rows)>=self.pub['n']:raise ValueError('Count wraps modulus')
        encrypted=[paillier_add([decode_integer(r['encrypted_indicators'][i],format_version(r)) for r in rows],self.pub) for i in range(conf['candidates'])]
        return {'encrypted_final_counts':encrypted,'final_counts':{str(i+1):paillier_decrypt(c,self.pub,self.priv) for i,c in enumerate(encrypted)},'note':'Two approvals simulate a threshold policy; private key remains in one local file'}

def main(directory=None):
    app=VotingApp(directory or Path(__file__).resolve().parents[1]/'demo_data'/'voting')
    print('EDUCATIONAL DEMONSTRATION ONLY: local clock is not a trusted timestamp authority;')
    print('voter keys are not bound to real identities; token lookup is not formal searchable encryption;')
    print('two fixed approval strings are not threshold decryption.')
    while True:
        print('\n1 Election Admin  2 Voter Client  3 Election Server  4 Tally Authorities  0 Exit')
        role=input('Role: ').strip()
        try:
            if role=='0':return
            if role=='1':app.setup(input('Start ISO UTC: '),input('End ISO UTC: '),int(input('Candidate count: ')));print('Election configured.')
            elif role=='2':
                item=app.cast(input('Ballot ID: '),int(input('Candidate ID: ')),input('Constituency: '))
                print('Encrypted ballot stored. SHA-512 (hex):',item['sha512'])
                print('AES-CBC IV (hex):',decode_bytes(item['aes_cbc']['iv'],2).hex())
                print('AES-CBC ballot ciphertext (hex):',decode_bytes(item['aes_cbc']['ciphertext'],2).hex())
                print('RSA-wrapped AES key (hex):',decode_bytes(item['wrapped_aes_key'],2).hex())
                print('ElGamal signature (hex):',{k:hex(v) for k,v in item['elgamal_signature'].items()})
                print('Paillier encrypted candidate ID (hex):',hex(decode_integer(item['encrypted_candidate_id'],2)))
                print('Paillier encrypted tally indicators (hex):',[hex(decode_integer(c,2)) for c in item['encrypted_indicators']])
            elif role=='3':
                print('1 Verify all  2 Search index');c=input('Choice: ')
                if c=='1':print([(r['ballot_id'],app.verify(r)) for r in app.rows()])
                elif c=='2':print(app.search(input('Constituency (blank all): ').strip() or None,input('Start UTC ISO (blank none): ').strip() or None,input('End UTC ISO (blank none): ').strip() or None))
                else:print('Invalid option.')
            elif role=='4':
                result=app.tally(input('Authority A approval code: '),input('Authority B approval code: '))
                encrypted_hex=[hex(c) for c in result.pop('encrypted_final_counts')]
                print({**result,'encrypted_final_counts_hex':encrypted_hex})
            else:print('Invalid role.')
        except (ValueError,KeyError,OSError) as exc:print('Operation failed:',exc)
if __name__=='__main__':main()
