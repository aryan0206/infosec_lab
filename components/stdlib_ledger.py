"""Standalone standard-library records engine for hash, search and audit exercises."""
import hashlib
import json
import sys
import tempfile
from pathlib import Path

CONFIG = {'family':'General records','features':['sha256','search','audit']}
MAX_AMOUNT=1_000_000_000_000

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
def digest(value,algorithm='sha256'):return hashlib.new(algorithm,canonical(value)).hexdigest()

class Ledger:
    def __init__(self,directory,config=None):
        self.config=config or CONFIG;self.features=set(self.config['features'])
        self.dir=Path(directory);self.dir.mkdir(parents=True,exist_ok=True)
        self.events_path=self.dir/'events.json'
    def enabled(self,feature):return feature in self.features
    def events(self):
        if not self.events_path.exists():return []
        try:rows=json.loads(self.events_path.read_text(encoding='utf-8'))
        except (OSError,json.JSONDecodeError) as exc:raise ValueError(f'Malformed stored event file: {exc}') from exc
        if not isinstance(rows,list):raise ValueError('Malformed event file: expected list')
        previous='0'*64;ids=set()
        for event in rows:
            if not isinstance(event,dict) or set(event)!={'type','payload','prev_hash','event_hash'} or event['type'] not in ('submission','decision') or not isinstance(event['payload'],dict):
                raise ValueError('Malformed event')
            if self.enabled('audit') and (event['prev_hash']!=previous or event['event_hash']!=digest({k:event[k] for k in ('type','payload','prev_hash')})):
                raise ValueError('Event hash chain failed')
            if event['type']=='submission':
                expense_id=event['payload'].get('expense_id')
                if not isinstance(expense_id,str) or not expense_id.strip() or expense_id in ids:raise ValueError('Invalid or duplicate stored ID')
                ids.add(expense_id)
            elif event['payload'].get('expense_id') not in ids:raise ValueError('Decision without submission')
            previous=event['event_hash']
        return rows
    def _append(self,kind,payload):
        rows=self.events();event={'type':kind,'payload':payload,'prev_hash':rows[-1]['event_hash'] if rows else '0'*64}
        event['event_hash']=digest(event);rows.append(event)
        temp=self.events_path.with_suffix('.tmp');temp.write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8');temp.replace(self.events_path)
    def records(self):return [e['payload'] for e in self.events() if e['type']=='submission']
    def find(self,expense_id):
        result=next((r for r in self.records() if r['expense_id']==expense_id),None)
        if result is None:raise ValueError('Expense ID not found')
        return result
    def protected(self,record):return {k:record[k] for k in ('expense_id','project_id','category','description','amount')}
    def record_hash(self,record):return digest(self.protected(record),'md5' if self.enabled('md5') else 'sha512' if self.enabled('sha512') else 'sha256')
    def verify_record(self,record):
        try:
            data=self.protected(record)
            if any(not isinstance(data[k],str) or not data[k].strip() for k in ('expense_id','project_id','category')):return False
            if not isinstance(data['description'],str) or type(data['amount']) is not int or not 0<=data['amount']<=MAX_AMOUNT:return False
            return not ({'sha256','sha512','md5'} & self.features) or record['record_hash']==self.record_hash(record)
        except (KeyError,TypeError,ValueError):return False
    def submit(self,expense_id,project_id,category,description,amount):
        if any(not isinstance(v,str) or not v.strip() for v in (expense_id,project_id,category,description)):
            raise ValueError('ID, project, category and description must be nonempty')
        if type(amount) is not int or not 0<=amount<=MAX_AMOUNT:raise ValueError('Amount must be integer 0..1000000000000')
        if any(r['expense_id']==expense_id for r in self.records()):raise ValueError('Duplicate Expense ID')
        record={'expense_id':expense_id,'project_id':project_id,'category':category,'description':description,'amount':amount}
        if {'sha256','sha512','md5'} & self.features:record['record_hash']=self.record_hash(record)
        self._append('submission',record);return record
    def latest_decision(self,expense_id):
        decisions=[e['payload'] for e in self.events() if e['type']=='decision' and e['payload']['expense_id']==expense_id]
        return decisions[-1] if decisions else None
    def decide(self,expense_id,decision,reason):
        if not self.enabled('approval'):raise ValueError('Approval disabled')
        record=self.find(expense_id)
        if not self.verify_record(record):raise ValueError('Record verification failed')
        if decision not in ('approved','rejected') or not reason.strip():raise ValueError('Decision and reason required')
        self._append('decision',{'expense_id':expense_id,'record_hash':self.record_hash(record),'decision':decision,'reason':reason})
    def search(self,expense_id):
        if not self.enabled('search'):raise ValueError('Search disabled')
        record=self.find(expense_id);decision=self.latest_decision(expense_id)
        return {'expense_id':expense_id,'project_id':record['project_id'],'category':record['category'],
                'decision':decision['decision'] if decision else 'pending','verified':self.verify_record(record)}

def self_test():
    with tempfile.TemporaryDirectory() as directory:
        app=Ledger(directory);app.submit('SELF1','P1','Test','First',120)
        if not app.verify_record(app.find('SELF1')):raise ValueError('Record hash check failed')
        if app.enabled('search') and not app.search('SELF1')['verified']:raise ValueError('Search failed')
        if app.enabled('approval'):app.decide('SELF1','approved','Test')
        again=Ledger(directory)
        if again.find('SELF1')['amount']!=120:raise ValueError('Restart failed')
        if app.enabled('audit'):
            rows=again.events();rows[0]['payload']['project_id']='ALTERED'
            again.events_path.write_text(json.dumps(rows),encoding='utf-8')
            try:again.events()
            except ValueError:pass
            else:raise ValueError('Tamper was not detected')
    print('SELF-TEST PASSED: standard-library records, restart and applicable checks.')

def main(directory=None):
    try:app=Ledger(directory or Path(__file__).resolve().parent/'demo_data'/Path(__file__).stem)
    except (OSError,ValueError) as exc:print('Startup failed:',exc);return
    print('Standard-library profile:',', '.join(sorted(app.features)))
    print('Plaintext records: no encryption or authenticated identity.')
    while True:
        try:
            print('\n1 Submit  2 View records  3 Search ID  4 Approve/reject  5 Verify event chain  0 Exit')
            choice=input('Choice: ').strip()
            if choice=='0':return
            if choice=='1':print('Saved:',app.submit(input('Expense ID: ').strip(),input('Project ID: ').strip(),input('Category: ').strip(),input('Description: '),int(input('Amount: ')))['expense_id'])
            elif choice=='2':print(app.records())
            elif choice=='3':print(app.search(input('Expense ID: ').strip()))
            elif choice=='4':app.decide(input('Expense ID: ').strip(),{'1':'approved','2':'rejected'}.get(input('1 Approve  2 Reject: ').strip()),input('Reason: ').strip());print('Decision saved')
            elif choice=='5':print('Events verified:',len(app.events()))
            else:print('Invalid choice.')
        except (ValueError,TypeError,KeyError,OSError) as exc:print('Operation failed:',exc)
        except (EOFError,KeyboardInterrupt):return

if __name__=='__main__':
    if '--self-test' in sys.argv:
        try:self_test()
        except (ValueError,OSError) as exc:print('SELF-TEST FAILED:',exc);raise SystemExit(1)
    else:main()
