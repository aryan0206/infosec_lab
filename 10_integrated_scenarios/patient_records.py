"""Question B menu. Run from project root: python 10_integrated_scenarios/patient_records.py"""
import csv,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import *
from store import *

class PatientApp:
    def __init__(self, directory):
        self.dir=Path(directory); self.dir.mkdir(parents=True,exist_ok=True)
        self.plain=self.dir/'Patient_records'; self.encrypted=self.dir/'encrypted_patient_records'
        self.aes,self.rsa,self.pub,self.priv=demo_keys(self.dir)
        self.pub=paillier_public(self.pub); self.priv=paillier_private(self.priv)
    def records(self):
        data=read_json(self.plain,[])
        if not isinstance(data,list): raise ValueError('Patient_records must contain a JSON list')
        return data
    def add(self,record):
        required={'Patient_id','Patient_name','Diagnosis','Blood_glucose','Treatment'}
        if set(record)!=required or not str(record['Patient_id']).strip(): raise ValueError('Five required fields and nonempty ID required')
        if type(record['Blood_glucose']) is not int or record['Blood_glucose']<0: raise ValueError('Blood glucose must be nonnegative integer')
        data=self.records()
        if any(str(r['Patient_id'])==str(record['Patient_id']) for r in data): raise ValueError('Duplicate patient ID')
        data.append(record); write_json(self.plain,data)
    def load_dataset(self,source_path):
        """Import a supplied JSON list or CSV table into an empty patient file once."""
        if self.records() or self.encrypted.exists():raise ValueError('Patient data already exists; import into a fresh directory')
        source=Path(source_path).expanduser()
        if source.suffix.casefold()=='.csv':
            with source.open('r',encoding='utf-8-sig',newline='') as stream:
                reader=csv.DictReader(stream)
                if set(reader.fieldnames or [])!={'Patient_id','Patient_name','Diagnosis','Blood_glucose','Treatment'}:
                    raise ValueError('CSV requires the five exact patient field names')
                try:data=[{**row,'Blood_glucose':int(row['Blood_glucose'])} for row in reader]
                except (TypeError,ValueError) as exc:raise ValueError('CSV blood glucose must be an integer') from exc
        elif source.suffix.casefold() in ('','.json'):
            data=json.loads(source.read_text(encoding='utf-8-sig'))
        else:raise ValueError('Use a JSON or CSV dataset file')
        if not isinstance(data,list) or not data:raise ValueError('Dataset must contain patient records')
        ids=set()
        for record in data:
            if not isinstance(record,dict) or set(record)!={'Patient_id','Patient_name','Diagnosis','Blood_glucose','Treatment'}:
                raise ValueError('Every patient needs the five exact fields')
            if not all(isinstance(record[field],str) for field in ('Patient_id','Patient_name','Diagnosis','Treatment')):
                raise ValueError('Patient text fields must be strings')
            if not record['Patient_id'].strip() or type(record['Blood_glucose']) is not int or record['Blood_glucose']<0:
                raise ValueError('Patient ID must be nonempty and glucose a nonnegative integer')
            if record['Patient_id'] in ids:raise ValueError('Duplicate patient ID')
            ids.add(record['Patient_id'])
        write_json(self.plain,data)
        return len(data)
    def encrypt_dataset(self):
        data=self.records()
        if not data: raise ValueError('Dataset empty')
        encrypted=[{'Patient_id':r['Patient_id'],'aes':aes_encrypt_record(canonical(r),self.aes,2)} for r in data]
        payload={'format_version':2,'records':encrypted,'plaintext_sha256':sha256(canonical(data))}
        write_json(self.encrypted,payload); return len(encrypted)
    def hash_record(self,patient_id):
        record=next((r for r in self.records() if str(r['Patient_id'])==str(patient_id)),None)
        if record is None: raise ValueError('Patient ID not found')
        return sha256(canonical(record))
    def sign_dataset(self):
        payload=read_json(self.encrypted,{})
        if not payload.get('records'): raise ValueError('Encrypt dataset first')
        version=format_version(payload)
        payload['signature']=rsa_sign_record(canonical({k:v for k,v in payload.items() if k!='signature'}),self.rsa,version)
        write_json(self.encrypted,payload)
    def verify(self):
        payload=read_json(self.encrypted,{})
        if not isinstance(payload,dict) or not isinstance(payload.get('records'),list): return False
        try:
            version=format_version(payload);sig=payload.get('signature')
            if not rsa_verify_record(canonical({k:v for k,v in payload.items() if k!='signature'}),sig,self.rsa.public_key(),version):return False
            decrypted=[__import__('json').loads(aes_decrypt_record(r['aes'],self.aes,version)) for r in payload['records']]
            return sha256(canonical(decrypted))==payload['plaintext_sha256'] and decrypted==self.records()
        except (KeyError,ValueError,TypeError,AttributeError,InvalidTag): return False
    def aggregate(self):
        data=self.records(); values=[r['Blood_glucose'] for r in data]
        if not values: raise ValueError('Dataset empty')
        if sum(values)>=self.pub['n']: raise ValueError('Sum wraps Paillier modulus')
        ciphertexts=[paillier_encrypt(v,self.pub) for v in values]
        c=paillier_add(ciphertexts,self.pub)
        return {'encrypted_sum':c,'decrypted_sum':paillier_decrypt(c,self.pub,self.priv),'expected':sum(values)}
    def search(self,diagnosis):
        if not self.verify(): raise ValueError('Verification failed; search blocked')
        payload=read_json(self.encrypted,{})
        version=format_version(payload)
        records=[__import__('json').loads(aes_decrypt_record(r['aes'],self.aes,version)) for r in payload['records']]
        return [r for r in records if diagnosis.casefold() in r['Diagnosis'].casefold()]
    def verified_record(self,patient_id):
        if not self.verify(): raise ValueError('Verification failed; decryption blocked')
        payload=read_json(self.encrypted,{})
        match=next((r for r in payload['records'] if str(r['Patient_id'])==str(patient_id)),None)
        if match is None: raise ValueError('Patient ID not found')
        return __import__('json').loads(aes_decrypt_record(match['aes'],self.aes,format_version(payload)))

def main(directory=None):
    app=PatientApp(directory or Path(__file__).resolve().parents[1]/'demo_data'/'patients')
    while True:
        print('\n1 Display dataset  2 AES encrypt  3 SHA-256 by ID  4 RSA sign dataset  5 Verify  6 Paillier glucose sum  7 Diagnosis search  8 Verified decrypt by ID  9 Exit  L Load supplied JSON/CSV')
        c=input('Choice: ').strip()
        try:
            if c=='9':return
            if c=='1':print(app.records())
            elif c=='2':print('Encrypted',app.encrypt_dataset(),'records into',app.encrypted)
            elif c=='3':print(app.hash_record(input('Patient ID: ')))
            elif c=='4':app.sign_dataset();print('Dataset signed.')
            elif c=='5':print('Verified' if app.verify() else 'Verification failed')
            elif c=='6':
                result=app.aggregate()
                print({'encrypted_sum_hex':hex(result['encrypted_sum']),'decrypted_sum':result['decrypted_sum'],'expected':result['expected']})
            elif c=='7':print('Verified matching patient records:',app.search(input('Diagnosis: ')))
            elif c=='8':print(app.verified_record(input('Patient ID: ')))
            elif c.casefold()=='l':print('Loaded',app.load_dataset(input('Dataset JSON/CSV path: ').strip()),'patient records; encrypt and sign next.')
            else:print('Invalid option.')
        except (ValueError,KeyError,OSError,InvalidTag) as exc:print('Operation failed:',exc)
if __name__=='__main__':main()
