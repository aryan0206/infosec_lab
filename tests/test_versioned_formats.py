"""Versioned record compatibility checks; all files live in temporary folders."""
import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import core

def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'10_integrated_scenarios'/f'{name}.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

PatientApp=load('patient_records').PatientApp
grant_module=load('grant_portal')
GrantApp=grant_module.GrantApp
VotingApp=load('e_voting_demo').VotingApp

class VersionedFormatTests(unittest.TestCase):
    def test_strict_codec_and_legacy_keys(self):
        self.assertEqual(core.decode_bytes('00abff',2),b'\x00\xab\xff')
        self.assertEqual(core.decode_integer('0xab',2),171)
        for bad in ('AB','a','0x12','gg',' aa'):
            with self.assertRaises(ValueError):core.decode_bytes(bad,2)
        for bad in ('ab','0xAB','0x','0xgg'):
            with self.assertRaises(ValueError):core.decode_integer(bad,2)
        for marker in (0,1,3,'2',True):
            with self.assertRaises(ValueError):core.format_version({'format_version':marker})
        with tempfile.TemporaryDirectory() as d:
            app=PatientApp(d)
            path=Path(d)/'keys.json'
            state=json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(state['format_version'],2)
            self.assertEqual(core.decode_bytes(state['aes'],2),app.aes)
            legacy={k:v for k,v in state.items() if k!='format_version'}
            legacy['aes']=core.b64(app.aes)
            path.write_text(json.dumps(legacy),encoding='utf-8')
            original=path.read_bytes()
            self.assertEqual(PatientApp(d).aes,app.aes)
            self.assertEqual(path.read_bytes(),original)
            legacy['format_version']=3
            path.write_text(json.dumps(legacy),encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'Unsupported format version'):PatientApp(d)

    def test_patient_v1_signature_unchanged_and_v2_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            app=PatientApp(d)
            record={'Patient_id':'P1','Patient_name':'Ada','Diagnosis':'Diabetes','Blood_glucose':110,'Treatment':'Diet'}
            app.add(record)
            legacy={'records':[{'Patient_id':'P1','aes':core.aes_encrypt(core.canonical(record),app.aes)}],
                    'plaintext_sha256':core.sha256(core.canonical([record]))}
            legacy['signature']=core.rsa_sign(core.canonical(legacy),app.rsa)
            app.encrypted.write_text(json.dumps(legacy),encoding='utf-8')
            old_bytes=app.encrypted.read_bytes()
            restarted=PatientApp(d)
            self.assertTrue(restarted.verify())
            self.assertEqual(restarted.search('diab'),[record])
            self.assertEqual(app.encrypted.read_bytes(),old_bytes)
        with tempfile.TemporaryDirectory() as d:
            app=PatientApp(d);app.add(record);app.encrypt_dataset();app.sign_dataset()
            saved=json.loads(app.encrypted.read_text(encoding='utf-8'))
            self.assertEqual(saved['format_version'],2)
            self.assertEqual(len(core.decode_bytes(saved['records'][0]['aes']['nonce'],2)),12)
            self.assertTrue(PatientApp(d).verify())
            for mutation in ('unknown_version','malformed_hex','changed_signature'):
                row=json.loads(json.dumps(saved))
                if mutation=='unknown_version':row['format_version']=3
                elif mutation=='malformed_hex':row['records'][0]['aes']['ciphertext']='GG'
                else:row['signature']='00'
                app.encrypted.write_text(json.dumps(row),encoding='utf-8')
                self.assertFalse(app.verify(),mutation)
                with self.assertRaises(ValueError):app.search('diab')

    def test_mixed_grants_both_legacy_signature_variants_and_v2(self):
        with tempfile.TemporaryDirectory() as d:
            app=GrantApp(d);app.submit('NEW','New',7)
            def old_record(identifier,amount,bounded):
                protected={'grant_id':identifier,'aes_description':core.aes_encrypt(identifier.encode(),app.aes),
                           'paillier_amount':str(core.paillier_encrypt(amount,app.pub))}
                digest=core.md5(core.canonical(protected))
                message=(grant_module.RANGE_POLICY if bounded else b'')+digest.encode()
                return {**protected,'md5':digest,'signature':core.rsa_sign(message,app.rsa)}
            rows=app.records()+[old_record('OLD_BOUND',5,True),old_record('OLD_UNBOUND',9,False)]
            app.path.write_text(json.dumps(rows),encoding='utf-8')
            original=app.path.read_bytes()
            again=GrantApp(d)
            self.assertEqual(again.path.read_bytes(),original)
            self.assertTrue(all(again.verified(r) for r in again.records()))
            self.assertEqual(again.aggregate(['NEW','OLD_BOUND'])['decrypted_final_total'],12)
            with self.assertRaisesRegex(ValueError,'predates the amount-bound policy'):
                again.aggregate(['OLD_UNBOUND'])
            self.assertEqual(again.path.read_bytes(),original)
            self.assertEqual(again.description_hex('OLD_BOUND'),b'OLD_BOUND'.hex())
            self.assertEqual(again.records()[0]['format_version'],2)
            self.assertTrue(again.records()[0]['paillier_amount'].startswith('0x'))
            for mutation in ('unknown_version','malformed_hex','tampered_amount'):
                altered=json.loads(json.dumps(rows))
                if mutation=='unknown_version':altered[0]['format_version']=3
                elif mutation=='malformed_hex':altered[0]['aes_description']['nonce']='GG'
                else:altered[0]['paillier_amount']='0x0'
                self.assertFalse(again.verified(altered[0]),mutation)
            malformed=json.loads(json.dumps(rows[0]))
            malformed['aes_description']['nonce']='GG'
            protected={k:malformed[k] for k in ('format_version','grant_id','aes_description','paillier_amount')}
            malformed['md5']=core.md5(core.canonical(protected))
            malformed['signature']=core.rsa_sign_record(grant_module.RANGE_POLICY+malformed['md5'].encode(),app.rsa,2)
            self.assertFalse(again.verified(malformed))
            self.assertEqual(again.path.read_bytes(),original)

    def test_mixed_voting_ballots_restart_and_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            now=datetime.now(timezone.utc)
            app=VotingApp(d,clock=lambda:now)
            app.setup((now-timedelta(days=1)).isoformat(),(now+timedelta(days=1)).isoformat(),2)
            app.cast('NEW',1,'North')
            ballot={'candidate_id':2,'constituency_id':'South'}
            raw=core.canonical(ballot);digest=__import__('hashlib').sha512(raw).digest()
            key=__import__('secrets').token_bytes(32)
            public,private=core.elgamal_keypair()
            legacy={'ballot_id':'OLD','timestamp':now.isoformat(),
                    'constituency_token':app.token('constituency','south'),
                    'day_token':app.token('day',now.date().isoformat()),
                    'sha512':digest.hex(),'aes_cbc':core.cbc_encrypt(raw,key),
                    'wrapped_aes_key':core.rsa_wrap(key,app.rsa.public_key()),
                    'elgamal_public':public,'elgamal_signature':core.elgamal_sign_digest(digest,public,private),
                    'encrypted_candidate_id':str(core.paillier_encrypt(2,app.pub)),
                    'encrypted_indicators':[str(core.paillier_encrypt(int(2==i),app.pub)) for i in (1,2)]}
            legacy['server_record_signature']=core.rsa_sign(core.canonical(legacy),app.rsa)
            rows=app.rows()+[legacy]
            app.path.write_text(json.dumps(rows),encoding='utf-8')
            original=app.path.read_bytes()
            closed=VotingApp(d,clock=lambda:now+timedelta(days=2))
            self.assertTrue(all(closed.verify(r) for r in closed.rows()))
            self.assertEqual(closed.tally('A','B')['final_counts'],{'1':1,'2':1})
            self.assertEqual(app.path.read_bytes(),original)
            self.assertEqual(rows[0]['format_version'],2)
            self.assertTrue(rows[0]['encrypted_candidate_id'].startswith('0x'))
            for mutation in ('unknown_version','malformed_hex','tampered_signature'):
                altered=json.loads(json.dumps(rows[0]))
                if mutation=='unknown_version':altered['format_version']=3
                elif mutation=='malformed_hex':altered['wrapped_aes_key']='GG'
                else:altered['server_record_signature']='00'
                self.assertFalse(closed.verify(altered),mutation)
            malformed=json.loads(json.dumps(rows[0]))
            malformed['encrypted_candidate_id']='0xGG'
            malformed['server_record_signature']=core.rsa_sign_record(core.canonical({k:v for k,v in malformed.items() if k!='server_record_signature'}),app.rsa,2)
            self.assertFalse(closed.verify(malformed))

if __name__=='__main__':unittest.main()
