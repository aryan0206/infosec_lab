"""Reusable signed network-record workflow; generated output is one standalone file."""
import hashlib
import hmac
import json
import socket
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asympad
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import *
from store import *

CONFIG = {'family':'Networked signed records','features':['tcp_framed','entity_keys','aes_gcm','rsa_oaep','paillier','replay','hmac_search','audit'], 'aes_bits':256,'hash_name':'sha256','hmac_hash':'sha256','roles':['Administrator','Sender','Receiver','Auditor'],'role_actions':{'Administrator':[1,2],'Sender':[3],'Receiver':[4],'Auditor':[5,6,7]},'labels':{'entity':'Entity ID','group':'Group','timestamp':'UTC timestamp','keyword':'Keyword','count':'Count','note':'Note'},'port':49152,'max_count':1000000000000}
MAX_FRAME=1_000_000

def digest_algorithm(config):
    name=config['hash_name']
    if name=='sha256':return hashes.SHA256()
    if name=='sha512':return hashes.SHA512()
    raise ValueError('Supported signing and OAEP hashes are SHA-256 and SHA-512')

def normalized_keyword(value):
    if not isinstance(value,str):raise ValueError('Keyword must be text')
    result=' '.join(value.casefold().split())
    if not result:raise ValueError('Keyword must be nonempty')
    return result

def frame_bytes(packet):
    data=canonical(packet)
    if not 0<len(data)<=MAX_FRAME:raise ValueError('Packet length outside allowed range')
    return str(len(data)).encode('ascii')+b'\n'+data

def read_frame(connection):
    connection.settimeout(3)
    reader=connection.makefile('rb')
    try:
        line=reader.readline(21)
        if not line.endswith(b'\n') or not line[:-1].isdigit():raise ValueError('Invalid decimal length line')
        length=int(line[:-1])
        if not 0<length<=MAX_FRAME:raise ValueError('Invalid packet length')
        payload=reader.read(length)
        if len(payload)!=length:raise ValueError('Incomplete packet')
        if reader.read(1):raise ValueError('Extra bytes after packet')
        try:return json.loads(payload.decode('utf-8'))
        except (UnicodeError,json.JSONDecodeError) as exc:raise ValueError('Malformed JSON packet') from exc
    finally:reader.close()

class NetworkRecords:
    def __init__(self,directory,config=None):
        self.config=config or CONFIG
        self.dir=Path(directory);self.dir.mkdir(parents=True,exist_ok=True)
        self.registry_path=self.dir/'entities.json'
        self.keys_path=self.dir/'receiver_keys.json'
        self.receiver_path=self.dir/'receiver_private.pem'
        self.events_path=self.dir/'accepted_events.json'

    def _entity_private_path(self,entity_id):return self.dir/('entity_'+sha256(entity_id.encode('utf-8'))[:24]+'_private.pem')
    def _entity_public_path(self,entity_id):return self.dir/('entity_'+sha256(entity_id.encode('utf-8'))[:24]+'_public.pem')

    def registry(self):
        data=read_json(self.registry_path,[])
        if not isinstance(data,list) or any(not isinstance(v,str) or not v.strip() for v in data) or len(set(data))!=len(data):
            raise ValueError('Malformed entity registry')
        return data

    def enroll(self,entity_id):
        if not isinstance(entity_id,str) or not entity_id.strip():raise ValueError('Entity ID must be nonempty')
        entities=self.registry()
        if entity_id in entities:raise ValueError('Duplicate Entity ID')
        private=self._entity_private_path(entity_id);public=self._entity_public_path(entity_id)
        if private.exists() or public.exists():raise ValueError('Existing key filename collision; enrolment blocked')
        key=rsa_keypair();save_private(private,key);save_public(public,key)
        entities.append(entity_id);write_json(self.registry_path,entities)
        return entity_id

    def setup_keys(self):
        if self.keys_path.exists()!=self.receiver_path.exists():raise ValueError('Incomplete receiver key state; restore original keys')
        if not self.keys_path.exists():
            if self.events_path.exists():raise ValueError('Accepted packets exist but receiver keys are missing')
            pub,priv=paillier_keypair()
            write_json(self.keys_path,{'paillier_public':pub,'paillier_private':priv,'search_key':secrets.token_bytes(32).hex()})
            save_private(self.receiver_path,rsa_keypair())
        state=read_json(self.keys_path,{})
        try:
            self.pub=paillier_public(state['paillier_public']);self.priv=paillier_private(state['paillier_private'])
            self.search_key=bytes.fromhex(state['search_key'])
            if len(self.search_key)!=32:raise ValueError('Invalid search key length')
            self.receiver=load_private(self.receiver_path)
        except (KeyError,TypeError,ValueError,OSError) as exc:raise ValueError(f'Malformed receiver keys: {exc}') from exc
        for entity_id in self.registry():
            if not self._entity_private_path(entity_id).is_file() or not self._entity_public_path(entity_id).is_file():
                raise ValueError('Enrolled entity key is missing: '+entity_id)
        return True

    def token(self,keyword):
        self.setup_keys()
        return hmac.new(self.search_key,normalized_keyword(keyword).encode('utf-8'),getattr(hashlib,self.config['hmac_hash'])).hexdigest()

    def signed_fields(self,packet):
        return {k:packet[k] for k in ('packet_id','entity_id','sequence','group','timestamp_utc','keyword','count_ciphertext','note_nonce','note_ciphertext','wrapped_key')}

    def sign(self,fields,private):
        algorithm=digest_algorithm(self.config)
        return private.sign(canonical(fields),asympad.PSS(mgf=asympad.MGF1(algorithm),salt_length=asympad.PSS.MAX_LENGTH),algorithm).hex()

    def verify_signature(self,packet):
        try:
            entity_id=packet['entity_id']
            if entity_id not in self.registry():return False
            public=load_public(self._entity_public_path(entity_id))
            algorithm=digest_algorithm(self.config)
            public.verify(bytes.fromhex(packet['signature']),canonical(self.signed_fields(packet)),
                          asympad.PSS(mgf=asympad.MGF1(algorithm),salt_length=asympad.PSS.MAX_LENGTH),algorithm)
            return True
        except (KeyError,TypeError,ValueError,OSError,InvalidSignature):return False

    def make_packet(self,entity_id,sequence,group,timestamp_utc,keyword,count,note):
        self.setup_keys()
        if entity_id not in self.registry():raise ValueError('Unknown Entity ID')
        if type(sequence) is not int or sequence<1:raise ValueError('Sequence must be a positive integer')
        if type(count) is not int or not 0<=count<=self.config['max_count'] or count>=self.pub['n']:
            raise ValueError('Count must be a nonnegative bounded integer below Paillier n')
        if not isinstance(group,str) or not group.strip() or not isinstance(note,str):raise ValueError('Group and note are required')
        normalized_keyword(keyword)
        self._check_timestamp(timestamp_utc)
        aes_key=secrets.token_bytes(self.config['aes_bits']//8)
        nonce=secrets.token_bytes(12)
        ciphertext=AESGCM(aes_key).encrypt(nonce,note.encode('utf-8'),None)
        algorithm=digest_algorithm(self.config)
        wrapped=self.receiver.public_key().encrypt(aes_key,asympad.OAEP(mgf=asympad.MGF1(algorithm),algorithm=algorithm,label=None))
        fields={'packet_id':f'{entity_id}:{sequence}','entity_id':entity_id,'sequence':sequence,'group':group,
                'timestamp_utc':timestamp_utc,'keyword':keyword,'count_ciphertext':hex(paillier_encrypt(count,self.pub)),
                'note_nonce':nonce.hex(),'note_ciphertext':ciphertext.hex(),'wrapped_key':wrapped.hex()}
        fields['signature']=self.sign(fields,load_private(self._entity_private_path(entity_id)))
        return fields

    def _check_timestamp(self,value):
        if not isinstance(value,str):raise ValueError('Timestamp must be UTC ISO text')
        try:parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
        except ValueError as exc:raise ValueError('Invalid UTC timestamp') from exc
        if parsed.tzinfo is None or parsed.utcoffset().total_seconds()!=0:raise ValueError('Timestamp must include UTC offset')

    def events(self):
        rows=read_json(self.events_path,[])
        if not isinstance(rows,list):raise ValueError('Malformed accepted-event file')
        previous='0'*64;ids=set()
        for event in rows:
            if not isinstance(event,dict) or set(event)!={'packet','search_token','prev_hash','event_hash'}:
                raise ValueError('Malformed accepted event')
            protected={k:event[k] for k in ('packet','search_token','prev_hash')}
            if event['prev_hash']!=previous or event['event_hash']!=sha256(canonical(protected)):
                raise ValueError('Accepted-event hash chain failed')
            packet=event['packet']
            if not isinstance(packet,dict) or packet.get('packet_id') in ids:raise ValueError('Duplicate or malformed stored packet')
            ids.add(packet['packet_id']);previous=event['event_hash']
        return rows

    def verified_events(self):
        rows=self.events()
        last={}
        for event in rows:
            packet=event['packet']
            if not self.verify_packet(packet):raise ValueError('Saved packet signature or fields failed verification')
            if event['search_token']!=self.token(packet['keyword']):raise ValueError('Saved search token failed verification')
            entity=packet['entity_id'];seq=packet['sequence']
            if seq<=last.get(entity,0):raise ValueError('Saved replay sequence is invalid')
            last[entity]=seq
        return rows,last

    def verify_packet(self,packet):
        try:
            if not isinstance(packet,dict) or set(packet)!=set(self.signed_fields(packet))|{'signature'}:return False
            fields=self.signed_fields(packet)
            if any(not isinstance(fields[k],str) or not fields[k].strip() for k in ('packet_id','entity_id','group','timestamp_utc','keyword')):return False
            if type(fields['sequence']) is not int or fields['sequence']<1 or fields['packet_id']!=f"{fields['entity_id']}:{fields['sequence']}":return False
            self._check_timestamp(fields['timestamp_utc']);normalized_keyword(fields['keyword'])
            for key in ('count_ciphertext','note_nonce','note_ciphertext','wrapped_key'):
                if not isinstance(fields[key],str):return False
            paillier_add([int(fields['count_ciphertext'],16)],self.pub)
            if len(bytes.fromhex(fields['note_nonce']))!=12:return False
            bytes.fromhex(fields['note_ciphertext']);bytes.fromhex(fields['wrapped_key'])
            return self.verify_signature(packet)
        except (KeyError,TypeError,ValueError):return False

    def accept_packet(self,packet):
        self.setup_keys()
        if not self.verify_packet(packet):raise ValueError('Unknown entity, missing fields, malformed values, or invalid signature')
        rows,last=self.verified_events()
        entity=packet['entity_id']
        if packet['sequence']<=last.get(entity,0):raise ValueError('Replay or non-increasing sequence rejected')
        # Unwrap and authenticate only after signature and replay checks. Rejected packets are not stored.
        self._decrypt_packet_note(packet)
        event={'packet':packet,'search_token':self.token(packet['keyword']),
               'prev_hash':rows[-1]['event_hash'] if rows else '0'*64}
        event['event_hash']=sha256(canonical(event))
        rows.append(event);write_json(self.events_path,rows)
        return packet['packet_id']

    def _decrypt_packet_note(self,packet):
        algorithm=digest_algorithm(self.config)
        key=self.receiver.decrypt(bytes.fromhex(packet['wrapped_key']),
                                  asympad.OAEP(mgf=asympad.MGF1(algorithm),algorithm=algorithm,label=None))
        if len(key)!=self.config['aes_bits']//8:raise ValueError('Wrapped AES key has wrong length')
        return AESGCM(key).decrypt(bytes.fromhex(packet['note_nonce']),bytes.fromhex(packet['note_ciphertext']),None).decode('utf-8')

    def find(self,packet_id):
        rows,_=self.verified_events()
        match=next((event['packet'] for event in rows if event['packet']['packet_id']==packet_id),None)
        if match is None:raise ValueError('Packet ID not found')
        return match

    def decrypt_note(self,packet_id):
        self.setup_keys();packet=self.find(packet_id)
        return self._decrypt_packet_note(packet)

    def search(self,keyword):
        self.setup_keys();rows,_=self.verified_events();wanted=self.token(keyword)
        return [{'packet_id':event['packet']['packet_id'],'verified':True} for event in rows if event['search_token']==wanted]

    def aggregate(self,packet_ids,group):
        self.setup_keys()
        if not packet_ids or len(set(packet_ids))!=len(packet_ids) or any(not item for item in packet_ids):
            raise ValueError('Select distinct nonempty Packet IDs')
        if not isinstance(group,str) or not group.strip():raise ValueError('Group is required')
        rows,_=self.verified_events();by_id={event['packet']['packet_id']:event['packet'] for event in rows}
        try:selected=[by_id[item] for item in packet_ids]
        except KeyError as exc:raise ValueError('Unknown Packet ID') from exc
        if any(packet['group']!=group for packet in selected):raise ValueError('Mixed-group selection rejected')
        if len(selected)*self.config['max_count']>=self.pub['n']:raise ValueError('Selected total might wrap Paillier modulus')
        ciphertext=paillier_add([int(packet['count_ciphertext'],16) for packet in selected],self.pub)
        return {'packet_ids':packet_ids,'group':group,'aggregate_ciphertext_hex':hex(ciphertext),
                'final_total':paillier_decrypt(ciphertext,self.pub,self.priv)}

class ReceiverServer:
    def __init__(self,records,port):
        self.records=records;self.sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.sock.bind(('127.0.0.1',port));self.sock.listen(5);self.sock.settimeout(0.2)
        self.port=self.sock.getsockname()[1];self.stop=threading.Event()
        self.thread=threading.Thread(target=self._loop,daemon=True);self.thread.start()
    def _loop(self):
        while not self.stop.is_set():
            try:conn,_=self.sock.accept()
            except socket.timeout:continue
            except OSError:break
            with conn:
                try:
                    packet=read_frame(conn)
                    result='ACCEPTED '+self.records.accept_packet(packet)
                except (ValueError,KeyError,TypeError,OSError,InvalidTag) as exc:result='REJECTED '+str(exc)
                try:conn.sendall((result+'\n').encode('utf-8'))
                except OSError:pass
    def close(self):
        self.stop.set();self.sock.close();self.thread.join(timeout=2)

def send_raw(raw,port):
    with socket.create_connection(('127.0.0.1',port),timeout=3) as conn:
        conn.settimeout(5);conn.sendall(raw);conn.shutdown(socket.SHUT_WR)
        return conn.makefile('rb').readline().decode('utf-8',errors='replace').strip()

def self_test():
    with tempfile.TemporaryDirectory() as directory:
        app=NetworkRecords(directory);app.enroll('E1');app.enroll('E2');app.setup_keys()
        server=ReceiverServer(app,0)
        try:
            now=datetime.now(timezone.utc).isoformat()
            packets=[app.make_packet('E1',1,'G1',now,'FIRE',4,'first'),
                     app.make_packet('E1',2,'G1',now,'FIRE',7,'second'),
                     app.make_packet('E2',1,'G1',now,'WIND',3,'third')]
            for packet in packets:
                if not send_raw(frame_bytes(packet),server.port).startswith('ACCEPTED'):raise ValueError('Valid packet rejected')
            if app.aggregate([p['packet_id'] for p in packets],'G1')['final_total']!=14:raise ValueError('Aggregate mismatch')
            if not send_raw(frame_bytes(packets[0]),server.port).startswith('REJECTED Replay'):raise ValueError('Replay accepted')
            if not send_raw(b'bad\n{}',server.port).startswith('REJECTED'):raise ValueError('Malformed frame accepted')
            changed=dict(packets[0]);changed['group']='OTHER';changed['sequence']=3;changed['packet_id']='E1:3'
            if not send_raw(frame_bytes(changed),server.port).startswith('REJECTED'):raise ValueError('Changed signed field accepted')
        finally:server.close()
        again=NetworkRecords(directory);again.setup_keys()
        if len(again.search('fire'))!=2 or again.decrypt_note('E1:1')!='first':raise ValueError('Restart/search/decrypt failed')
        if again.aggregate(['E1:1','E1:2','E2:1'],'G1')['final_total']!=14:raise ValueError('Restart aggregate failed')
    print('SELF-TEST PASSED: framed TCP, signatures, replay, AES, Paillier, search, restart.')

def main(directory=None):
    app=NetworkRecords(directory or Path(__file__).resolve().parents[1]/'demo_data'/Path(__file__).stem)
    server=None
    labels=app.config['labels'];roles=app.config['roles']
    print('Workflow role menus are not identity authentication. Sender timestamps are not trusted timestamps.')
    actions={1:'Enrol entity',2:'Create/load receiver, Paillier and search keys',3:'Send framed packet',
             4:'Start local receiver',5:'Exact keyword search',6:'Verify/decrypt note',7:'Encrypted aggregate'}
    try:
        while True:
            try:
                print('\n'+'  '.join(f'{i} {name}' for i,name in enumerate(roles,1))+'  0 Exit')
                role=input('Role: ').strip()
                if role=='0':return
                if not role.isdecimal() or not 1<=int(role)<=len(roles):print('Invalid role.');continue
                name=roles[int(role)-1];allowed=app.config['role_actions'][name]
                print(name+': '+'  '.join(f'{i} {actions[i]}' for i in allowed)+'  0 Back')
                choice=input('Choice: ').strip()
                if choice=='0':continue
                if not choice.isdecimal() or int(choice) not in allowed:print('Invalid option for role.');continue
                action=int(choice)
                if action==1:print('Enrolled:',app.enroll(input(labels['entity']+': ').strip()))
                elif action==2:app.setup_keys();print('Persistent keys ready.')
                elif action==3:
                    packet=app.make_packet(input(labels['entity']+': ').strip(),int(input('Increasing sequence: ')),
                        input(labels['group']+': ').strip(),input(labels['timestamp']+' (ISO 8601): ').strip(),
                        input(labels['keyword']+': ').strip(),int(input(labels['count']+' (integer): ')),input(labels['note']+': '))
                    print('Receiver response:',send_raw(frame_bytes(packet),app.config['port']))
                elif action==4:
                    if server is None:
                        app.setup_keys();server=ReceiverServer(app,app.config['port']);print('Receiver listening on 127.0.0.1:',server.port)
                    else:print('Receiver already listening on 127.0.0.1:',server.port)
                elif action==5:print(app.search(input(labels['keyword']+': ')))
                elif action==6:print('Verified note:',app.decrypt_note(input('Packet ID: ').strip()))
                elif action==7:print(app.aggregate([v.strip() for v in input('Packet IDs, comma-separated: ').split(',')],input(labels['group']+': ').strip()))
            except (ValueError,KeyError,TypeError,OSError,InvalidTag) as exc:print('Operation failed:',exc)
            except (EOFError,KeyboardInterrupt):return
    finally:
        if server is not None:server.close()

if __name__=='__main__':
    if '--self-test' in sys.argv:
        try:self_test()
        except (ValueError,OSError,InvalidTag) as exc:print('SELF-TEST FAILED:',exc);raise SystemExit(1)
    else:main()
