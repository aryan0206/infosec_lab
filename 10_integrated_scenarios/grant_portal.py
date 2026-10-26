"""Question C educational Grant Expense Portal. Role menus are workflow controls only."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import *
from store import *

# The signed policy distinguishes bounded new records from older, unbounded ones
# without changing the stored JSON structure or decrypting individual amounts.
MAX_GRANT_AMOUNT=1_000_000_000_000
RANGE_POLICY=b'grant amount 0..1000000000000;'

def checked_total_capacity(count,modulus):
    if type(count) is not int or count<1 or type(modulus) is not int or modulus<2:
        raise ValueError('Invalid aggregate count or Paillier modulus')
    upper=count*MAX_GRANT_AMOUNT
    if upper>=modulus: raise ValueError('Selected total may wrap Paillier modulus; aggregate blocked')
    return upper

class GrantApp:
    def __init__(self,directory):
        self.dir=Path(directory);self.dir.mkdir(parents=True,exist_ok=True)
        self.path=self.dir/'grants.json'
        self.aes,self.rsa,self.pub,self.priv=demo_keys(self.dir)
        self.pub=paillier_public(self.pub);self.priv=paillier_private(self.priv)
    def records(self):
        rows=read_json(self.path,[])
        if not isinstance(rows,list):raise ValueError('Malformed grants file')
        return rows
    def submitted_views(self):
        """Show every saved submission without decrypting description or amount."""
        views=[]
        for record in self.records():
            version=format_version(record)
            views.append({
                'grant_id':record['grant_id'],
                'aes_nonce_hex':decode_bytes(record['aes_description']['nonce'],version).hex(),
                'aes_ciphertext_hex':decode_bytes(record['aes_description']['ciphertext'],version).hex(),
                'paillier_ciphertext_hex':hex(decode_integer(record['paillier_amount'],version)),
                'md5_hex':record['md5'],
                'signature_hex':decode_bytes(record['signature'],version).hex(),
                'verified':self.verified(record),
            })
        return views
    def submit(self,grant_id,description,amount):
        if not grant_id.strip() or not description.strip() or type(amount) is not int or not 0<=amount<=MAX_GRANT_AMOUNT or amount>=self.pub['n']:raise ValueError('Nonempty ID/description and amount in 0..1000000000000 below n required')
        rows=self.records()
        if any(r['grant_id']==grant_id for r in rows):raise ValueError('Duplicate Grant ID')
        protected={'format_version':2,'grant_id':grant_id,'aes_description':aes_encrypt_record(description.encode(),self.aes,2),'paillier_amount':encode_integer(paillier_encrypt(amount,self.pub),2)}
        digest=md5(canonical(protected))
        record={**protected,'md5':digest,'signature':rsa_sign_record(RANGE_POLICY+digest.encode(),self.rsa,2)}
        rows.append(record);write_json(self.path,rows);return record
    def verified(self,record):
        try:
            version=format_version(record)
            fields=('grant_id','aes_description','paillier_amount') if version==1 else ('format_version','grant_id','aes_description','paillier_amount')
            protected={k:record[k] for k in fields}
            digest=md5(canonical(protected))
            if digest!=record['md5']:return False
            if version==2:
                decode_bytes(record['aes_description']['nonce'],2)
                decode_bytes(record['aes_description']['ciphertext'],2)
                decode_integer(record['paillier_amount'],2)
                return rsa_verify_record(RANGE_POLICY+digest.encode(),record['signature'],self.rsa.public_key(),version)
            return rsa_verify_record(RANGE_POLICY+digest.encode(),record['signature'],self.rsa.public_key(),version) or rsa_verify_record(digest.encode(),record['signature'],self.rsa.public_key(),version)
        except (KeyError,TypeError,ValueError):return False
    def bounded_record(self,record):
        if not self.verified(record): return False
        return rsa_verify_record(RANGE_POLICY+record['md5'].encode(),record['signature'],self.rsa.public_key(),format_version(record))
    def find(self,grant_id):
        record=next((r for r in self.records() if r['grant_id']==grant_id),None)
        if record is None:raise ValueError('Grant ID not found')
        return record
    def search(self,grant_id):
        r=self.find(grant_id);return {'grant_id':r['grant_id'],'verified':self.verified(r)}
    def description_hex(self,grant_id):
        r=self.find(grant_id)
        if not self.verified(r):raise ValueError('Tampering detected; decrypt blocked')
        return aes_decrypt_record(r['aes_description'],self.aes,format_version(r)).hex()
    def aggregate(self,ids):
        if not ids or len(set(ids))!=len(ids):raise ValueError('Select distinct existing IDs')
        selected=[self.find(i) for i in ids]
        if any(not self.verified(r) for r in selected):raise ValueError('Signature/hash failure; tally blocked')
        if any(not self.bounded_record(r) for r in selected):raise ValueError('Selected grant predates the amount-bound policy; re-submit it before tallying')
        checked_total_capacity(len(selected),self.pub['n'])
        encrypted=paillier_add([decode_integer(r['paillier_amount'],format_version(r)) for r in selected],self.pub)
        return {'selected_ids':ids,'encrypted_total':encrypted,'decrypted_final_total':paillier_decrypt(encrypted,self.pub,self.priv),'note':'Individual amounts were not decrypted'}

def main(directory=None):
    app=GrantApp(directory or Path(__file__).resolve().parents[1]/'demo_data'/'grants')
    while True:
        print('\n1 Researcher  2 Reviewer  3 Finance Officer  0 Exit')
        role=input('Role: ').strip()
        if role=='0':return
        if role not in ('1','2','3'):print('Invalid role.');continue
        while True:
            choices={'1':'1 Submit grant  2 View all submitted grants (encrypted fields)  0 Back','2':'1 Verify all  2 Search Grant ID (metadata only)  3 Decrypted description hex  0 Back','3':'1 Aggregate selected grants  0 Back'}
            print('\n'+choices[role]);choice=input('Choice: ').strip()
            if choice=='0':break
            try:
                if role=='1' and choice=='1':
                    r=app.submit(input('Grant ID: ').strip(),input('Description: '),int(input('Amount (integer units): ')));print('Submitted:',r['grant_id'])
                elif role=='1' and choice=='2':
                    views=app.submitted_views()
                    if not views:print('No submitted grants yet.')
                    for view in views:
                        print('\nGrant ID:',view['grant_id'])
                        print('AES nonce (hex):',view['aes_nonce_hex'])
                        print('AES encrypted description (hex):',view['aes_ciphertext_hex'])
                        print('Paillier encrypted amount (hex integer):',view['paillier_ciphertext_hex'])
                        print('MD5 record hash (hex):',view['md5_hex'])
                        print('RSA signature (hex):',view['signature_hex'])
                        print('Verification:', 'passed' if view['verified'] else 'FAILED')
                elif role=='2' and choice=='1':print([(r['grant_id'],app.verified(r)) for r in app.records()])
                elif role=='2' and choice=='2':print(app.search(input('Grant ID: ').strip()))
                elif role=='2' and choice=='3':print('Description UTF-8 hex:',app.description_hex(input('Grant ID: ').strip()))
                elif role=='3' and choice=='1':
                    result=app.aggregate([i.strip() for i in input('Selected Grant IDs, comma-separated: ').split(',')])
                    encrypted_hex=hex(result.pop('encrypted_total'))
                    print({**result,'encrypted_total_hex':encrypted_hex})
                else:print('Invalid option for role.')
            except (ValueError,KeyError,OSError,InvalidTag) as exc:print('Operation failed:',exc)
if __name__=='__main__':main()
