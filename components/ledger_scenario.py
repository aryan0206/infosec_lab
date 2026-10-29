"""Configurable local exam ledger. Source for one-file exports; roles are menu labels, not authentication."""
import sys
import tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import *
from store import *

CONFIG = {'family':'General records','features':['aes','paillier','sha256','researcher_sig','reviewer_sig','approval','audit','search','aggregate','roles'],'aes_bits':192}
MAX_AMOUNT = 1_000_000_000_000

class Ledger:
    def __init__(self,directory,config=None):
        self.config=config or CONFIG
        self.features=set(self.config['features'])
        self.dir=Path(directory);self.dir.mkdir(parents=True,exist_ok=True)
        self.events_path=self.dir/'events.json'
        self.keys_path=self.dir/'keys.json'
        self.researcher_path=self.dir/'researcher_private.pem'
        self.reviewer_path=self.dir/'reviewer_private.pem'
        self._keys()

    def enabled(self,feature):return feature in self.features

    def _keys(self):
        needed=[self.keys_path]
        if self.enabled('researcher_sig'):needed.append(self.researcher_path)
        if self.enabled('reviewer_sig'):needed.append(self.reviewer_path)
        existence=[p.exists() for p in needed]
        if any(existence) and not all(existence):raise ValueError('Incomplete key files; restore the original key files before continuing')
        if not any(existence) and self.events_path.exists():
            raise ValueError('Stored events exist but keys are missing; restore the original key files')
        if not any(existence):
            state={}
            if self.enabled('aes'):state['aes']=secrets.token_bytes(self.config.get('aes_bits',192)//8).hex()
            if self.enabled('paillier'):
                public,private=paillier_keypair()
                state['paillier_public']=public;state['paillier_private']=private
            write_json(self.keys_path,state)
            if self.enabled('researcher_sig'):save_private(self.researcher_path,rsa_keypair())
            if self.enabled('reviewer_sig'):save_private(self.reviewer_path,rsa_keypair())
        state=read_json(self.keys_path,{})
        if not isinstance(state,dict):raise ValueError('Malformed key file')
        try:
            self.aes=bytes.fromhex(state['aes']) if self.enabled('aes') else None
            if self.aes is not None and len(self.aes)!=self.config.get('aes_bits',192)//8:raise ValueError('AES key length does not match selected profile')
            self.pub=paillier_public(state['paillier_public']) if self.enabled('paillier') else None
            self.priv=paillier_private(state['paillier_private']) if self.enabled('paillier') else None
            self.researcher=load_private(self.researcher_path) if self.enabled('researcher_sig') else None
            self.reviewer=load_private(self.reviewer_path) if self.enabled('reviewer_sig') else None
        except (KeyError,TypeError,ValueError,OSError) as exc:raise ValueError(f'Malformed or unreadable key state: {exc}') from exc

    def events(self):
        rows=read_json(self.events_path,[])
        if not isinstance(rows,list):raise ValueError('Malformed event file: expected a list')
        previous='0'*64
        ids=set()
        for i,event in enumerate(rows):
            if not isinstance(event,dict) or set(event)!={'type','payload','prev_hash','event_hash'}:
                raise ValueError(f'Malformed event at position {i+1}')
            if event['type'] not in ('submission','decision') or not isinstance(event['payload'],dict):
                raise ValueError(f'Malformed event payload at position {i+1}')
            if self.enabled('audit') and (event['prev_hash']!=previous or event['event_hash']!=sha256(canonical({k:event[k] for k in ('type','payload','prev_hash')}))):
                raise ValueError(f'Event hash chain failed at position {i+1}')
            if event['type']=='submission':
                expense_id=event['payload'].get('expense_id')
                if not isinstance(expense_id,str) or not expense_id.strip() or expense_id in ids:raise ValueError('Duplicate or malformed stored Expense ID')
                ids.add(expense_id)
            elif event['payload'].get('expense_id') not in ids:raise ValueError('Decision without a preceding expense')
            previous=event['event_hash']
        return rows

    def _append(self,kind,payload):
        rows=self.events()
        event={'type':kind,'payload':payload,'prev_hash':rows[-1]['event_hash'] if rows else '0'*64}
        event['event_hash']=sha256(canonical(event))
        rows.append(event);write_json(self.events_path,rows)
        return event

    def records(self):return [e['payload'] for e in self.events() if e['type']=='submission']

    def find(self,expense_id):
        record=next((r for r in self.records() if r['expense_id']==expense_id),None)
        if record is None:raise ValueError('Expense ID not found')
        return record

    def protected(self,record):
        return {k:record[k] for k in ('expense_id','project_id','category','description','amount')}

    def record_hash(self,record):
        if self.enabled('md5'):return md5(canonical(self.protected(record)))
        if self.enabled('sha512'):return sha512(canonical(self.protected(record)))
        return sha256(canonical(self.protected(record)))

    def _signature_algorithm(self):return hashes.SHA512() if self.enabled('sha512') else hashes.SHA256()
    def _sign(self,data,private):
        algorithm=self._signature_algorithm()
        return b64(private.sign(data,asympad.PSS(mgf=asympad.MGF1(algorithm),salt_length=asympad.PSS.MAX_LENGTH),algorithm))
    def _verify(self,data,signature,public):
        try:
            algorithm=self._signature_algorithm()
            public.verify(unb64(signature),data,asympad.PSS(mgf=asympad.MGF1(algorithm),salt_length=asympad.PSS.MAX_LENGTH),algorithm)
            return True
        except (InvalidSignature,ValueError,TypeError):return False

    def verify_record(self,record):
        try:
            protected=self.protected(record)
            if any(not isinstance(protected[k],str) or not protected[k].strip() for k in ('expense_id','project_id','category')):return False
            if self.enabled('aes'):
                blob=record['description']
                if not isinstance(blob,dict) or set(blob)!={'nonce','ciphertext'}:return False
                decode_bytes(blob['nonce'],2);decode_bytes(blob['ciphertext'],2)
            elif not isinstance(record['description'],str):return False
            if self.enabled('paillier'):
                c=int(record['amount'],16)
                paillier_add([c],self.pub)
            elif type(record['amount']) is not int or not 0<=record['amount']<=MAX_AMOUNT:return False
            digest=self.record_hash(record)
            if self.enabled('sha256') or self.enabled('sha512') or self.enabled('md5'):
                if digest!=record['record_hash']:return False
            if self.enabled('researcher_sig'):
                if not self._verify(bytes.fromhex(digest),record['researcher_signature'],self.researcher.public_key()):return False
            return True
        except (KeyError,TypeError,ValueError,InvalidTag):return False

    def submit(self,expense_id,project_id,category,description,amount):
        for label,value in [('Expense ID',expense_id),('Project ID',project_id),('Category',category),('Description',description)]:
            if not isinstance(value,str) or not value.strip():raise ValueError(f'{label} must be nonempty')
        if type(amount) is not int or not 0<=amount<=MAX_AMOUNT:raise ValueError('Amount must be an integer from 0 to 1000000000000')
        if any(r['expense_id']==expense_id for r in self.records()):raise ValueError('Duplicate Expense ID')
        protected={'expense_id':expense_id,'project_id':project_id,'category':category,
                   'description':aes_encrypt_record(description.encode('utf-8'),self.aes,2) if self.enabled('aes') else description,
                   'amount':hex(paillier_encrypt(amount,self.pub)) if self.enabled('paillier') else amount}
        record=dict(protected)
        digest=self.record_hash(record)
        if self.enabled('sha256') or self.enabled('sha512') or self.enabled('md5'):record['record_hash']=digest
        if self.enabled('researcher_sig'):record['researcher_signature']=self._sign(bytes.fromhex(digest),self.researcher)
        self._append('submission',record)
        return record

    def latest_decision(self,expense_id):
        matches=[e['payload'] for e in self.events() if e['type']=='decision' and e['payload']['expense_id']==expense_id]
        return matches[-1] if matches else None

    def verify_decision(self,decision,record):
        try:
            base={k:decision[k] for k in ('expense_id','record_hash','decision','reason')}
            if base['expense_id']!=record['expense_id'] or base['record_hash']!=self.record_hash(record):return False
            if base['decision'] not in ('approved','rejected') or not isinstance(base['reason'],str) or not base['reason'].strip():return False
            if self.enabled('reviewer_sig') and not self._verify(canonical(base),decision['reviewer_signature'],self.reviewer.public_key()):return False
            return True
        except (KeyError,TypeError,ValueError):return False

    def decide(self,expense_id,decision,reason):
        if not self.enabled('approval'):raise ValueError('Approval workflow is disabled')
        record=self.find(expense_id)
        if not self.verify_record(record):raise ValueError('Record verification failed; decision blocked')
        if decision not in ('approved','rejected') or not reason.strip():raise ValueError('Choose approved/rejected and enter a reason')
        previous=self.latest_decision(expense_id)
        if previous and not self.verify_decision(previous,record):raise ValueError('Previous decision verification failed')
        base={'expense_id':expense_id,'record_hash':self.record_hash(record),'decision':decision,'reason':reason}
        payload=dict(base)
        if self.enabled('reviewer_sig'):payload['reviewer_signature']=self._sign(canonical(base),self.reviewer)
        self._append('decision',payload)
        return payload

    def search(self,expense_id):
        if not self.enabled('search'):raise ValueError('Search is disabled')
        record=self.find(expense_id)
        decision=self.latest_decision(expense_id)
        valid=self.verify_record(record) and (decision is None or self.verify_decision(decision,record))
        return {'expense_id':expense_id,'project_id':record['project_id'],'category':record['category'],
                'decision':decision['decision'] if decision else 'pending','verified':valid}

    def description_hex(self,expense_id):
        record=self.find(expense_id)
        if not self.verify_record(record):raise ValueError('Record verification failed; decrypt blocked')
        data=aes_decrypt_record(record['description'],self.aes,2) if self.enabled('aes') else record['description'].encode('utf-8')
        return data.hex()

    def prior_submissions(self):
        views=[]
        for record in self.records():
            views.append({'expense_id':record['expense_id'],'project_id':record['project_id'],'category':record['category'],
                          'description_ciphertext':record['description'] if self.enabled('aes') else None,
                          'description_plaintext':None if self.enabled('aes') else record['description'],
                          'amount_ciphertext_hex':record['amount'] if self.enabled('paillier') else None,
                          'amount_plaintext':None if self.enabled('paillier') else record['amount'],
                          'verified':self.verify_record(record)})
        return views

    def aggregate(self,ids,project_id,budget):
        if not self.enabled('aggregate'):raise ValueError('Aggregation is disabled')
        if not ids or len(set(ids))!=len(ids) or any(not i for i in ids):raise ValueError('Select distinct nonempty Expense IDs')
        if type(budget) is not int or budget<0:raise ValueError('Budget must be a nonnegative integer')
        selected=[self.find(i) for i in ids]
        if any(r['project_id']!=project_id for r in selected):raise ValueError('Mixed-project selection blocked')
        if any(not self.verify_record(r) for r in selected):raise ValueError('Record verification failed; aggregation blocked')
        if self.enabled('approval'):
            for record in selected:
                decision=self.latest_decision(record['expense_id'])
                if decision is None or not self.verify_decision(decision,record) or decision['decision']!='approved':
                    raise ValueError('Missing, rejected, or invalid approval; aggregation blocked')
        if self.enabled('paillier'):
            if len(ids)*MAX_AMOUNT>=self.pub['n']:raise ValueError('Selected total might wrap the Paillier modulus')
            ciphertext=paillier_add([int(r['amount'],16) for r in selected],self.pub)
            total=paillier_decrypt(ciphertext,self.pub,self.priv)
            encrypted=hex(ciphertext)
        else:
            total=sum(r['amount'] for r in selected)
            encrypted=None
        return {'selected_ids':ids,'aggregate_ciphertext_hex':encrypted,'final_total':total,'exceeds_budget':total>budget}

def demo(app):
    for expense_id,amount,decision in [('E1',120,'approved'),('E2',80,'approved'),('E3',50,'rejected')]:
        if not any(r['expense_id']==expense_id for r in app.records()):app.submit(expense_id,'P1','Lab','Demo expense '+expense_id,amount)
        if app.enabled('approval') and app.latest_decision(expense_id) is None:app.decide(expense_id,decision,'Demo decision')
    print('Demo records E1=120, E2=80, E3=50 saved. P1 budget 300.')
    if app.enabled('aggregate'):print('E1+E2:',app.aggregate(['E1','E2'],'P1',300))

def self_test():
    """Exercise selected components in isolated temporary storage, including restart and tamper rejection."""
    with tempfile.TemporaryDirectory() as directory:
        app=Ledger(directory)
        app.submit('SELF1','P1','Test','First',120)
        app.submit('SELF2','P1','Test','Second',80)
        if not app.verify_record(app.find('SELF1')):raise ValueError('Record verification failed')
        if app.enabled('search') and not app.search('SELF1')['verified']:raise ValueError('Search verification failed')
        if app.enabled('aes') and app.description_hex('SELF1')!='First'.encode().hex():raise ValueError('AES round trip failed')
        if app.enabled('approval'):
            app.decide('SELF1','approved','Test approval')
            app.decide('SELF2','approved','Test approval')
        again=Ledger(directory)
        if again.find('SELF1')['expense_id']!='SELF1':raise ValueError('Restart persistence failed')
        if app.enabled('aggregate') and again.aggregate(['SELF1','SELF2'],'P1',300)['final_total']!=200:
            raise ValueError('Aggregate check failed')
        if app.enabled('audit'):
            rows=again.events();rows[0]['payload']['project_id']='ALTERED'
            write_json(again.events_path,rows)
            try:again.events()
            except ValueError:pass
            else:raise ValueError('Event tamper was not detected')
    print('SELF-TEST PASSED: selected features, restart, and applicable tamper checks.')

def main(directory=None):
    try:app=Ledger(directory or Path(__file__).resolve().parents[1]/'demo_data'/Path(__file__).stem)
    except (ValueError,OSError) as exc:print('Startup failed:',exc,'Restore key/data files or use a new submission filename.');return
    print('Enabled features:',', '.join(sorted(app.features)))
    print('Role menus guide workflow; they do not authenticate users.')
    role=None
    role_choices={'1':('Researcher',{'1','2','8'}),'2':('Reviewer',{'3','4','5','7'}),
                  '3':('Finance officer',{'6','7'}),'4':('Administrator',{'2','7','8'})}
    while True:
        try:
            if app.enabled('roles') and role is None:
                print('\n1 Researcher  2 Reviewer  3 Finance officer  4 Administrator  0 Exit')
                role=input('Role: ').strip()
                if role=='0':return
                if role not in role_choices:print('Invalid role.');role=None;continue
            if app.enabled('roles'):
                title,allowed=role_choices[role]
                labels={'1':'Submit expense','2':'View earlier submissions','3':'Search ID',
                        '4':'Verify/decrypt description hex','5':'Approve/reject',
                        '6':'Aggregate selected IDs','7':'Verify event chain','8':'Load demo records'}
                print('\n'+title+': '+'  '.join(f'{n} {labels[n]}' for n in sorted(allowed))+'  9 Change role  0 Exit')
            else:
                print('\n1 Submit expense  2 View earlier submissions  3 Search ID  4 Verify/decrypt description hex')
                print('5 Approve/reject  6 Aggregate selected IDs  7 Verify event chain  8 Load demo records  0 Exit')
            choice=input('Choice: ').strip()
            if choice=='0':return
            if app.enabled('roles') and choice=='9':role=None;continue
            if app.enabled('roles') and choice not in role_choices[role][1]:print('Invalid option for role.');continue
            if choice=='1':print('Saved:',app.submit(input('Expense ID: ').strip(),input('Project ID: ').strip(),input('Category: ').strip(),input('Description: '),int(input('Amount (nonnegative integer): ')))['expense_id'])
            elif choice=='2':
                for row in app.prior_submissions():print(row)
            elif choice=='3':print(app.search(input('Expense ID: ').strip()))
            elif choice=='4':print('Description UTF-8 hex:',app.description_hex(input('Expense ID: ').strip()))
            elif choice=='5':
                decision={'1':'approved','2':'rejected'}.get(input('1 Approve  2 Reject: ').strip())
                print('Decision saved:',app.decide(input('Expense ID: ').strip(),decision,input('Reason: ').strip())['decision'])
            elif choice=='6':print(app.aggregate([v.strip() for v in input('Expense IDs, comma-separated: ').split(',')],input('Project ID: ').strip(),int(input('Project budget: '))))
            elif choice=='7':print('Event chain valid:',len(app.events()),'events')
            elif choice=='8':demo(app)
            else:print('Invalid choice; choose a listed number.')
        except (ValueError,KeyError,TypeError,OSError,InvalidTag) as exc:print('Operation failed:',exc)
        except (EOFError,KeyboardInterrupt):print('\nExited.');return

if __name__=='__main__':
    if '--self-test' in sys.argv:
        try:self_test()
        except (ValueError,OSError,InvalidTag) as exc:
            print('SELF-TEST FAILED:',exc)
            raise SystemExit(1)
    else:main()
