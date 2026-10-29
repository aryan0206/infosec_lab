"""Generic network component tests, using the sensor question as one configured acceptance case."""
import ast
import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import master_builder as builder

def generated(directory,options=None):
    with patch.object(builder,'OUTPUT',Path(directory)):
        path,report,features=builder.build('6',{'tcp_framed'},options)
        validation=builder.validate(path)
    spec=importlib.util.spec_from_file_location('generated_network',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return path,report,features,validation,module

class NetworkBuilderTests(unittest.TestCase):
    def sensor_options(self):
        return {'aes_bits':256,'hash_name':'sha256','hmac_hash':'sha256',
                'roles':['Administrator','Sensor sender','Receiver','Auditor'],
                'labels':{'entity':'Sensor ID','group':'Station','timestamp':'UTC timestamp','keyword':'Alert keyword','count':'Event count','note':'Note'},
                'port':49152,'max_count':1_000_000_000_000}

    def test_sensor_acceptance_tcp_replay_search_aggregate_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path,report,features,validation,m=generated(d,self.sensor_options())
            self.assertIn('functional self-test PASSED',validation)
            self.assertEqual(m.CONFIG['labels']['group'],'Station')
            self.assertEqual(m.CONFIG['roles'][1],'Sensor sender')
            self.assertEqual(m.CONFIG['aes_bits'],256)
            tree=ast.parse(path.read_text(encoding='utf-8'))
            self.assertFalse(any(isinstance(n,ast.ImportFrom) and n.module in {'core','store','master_builder'} for n in ast.walk(tree)))
            self.assertNotIn('sys.path.insert(',path.read_text(encoding='utf-8'))
            data=Path(d)/'runtime';app=m.NetworkRecords(data)
            app.enroll('S1');app.enroll('S2')
            with self.assertRaisesRegex(ValueError,'Duplicate'):app.enroll('S1')
            app.setup_keys()
            self.assertTrue((data/'receiver_private.pem').is_file())
            self.assertTrue((data/'receiver_keys.json').is_file())
            now=datetime.now(timezone.utc).isoformat()
            p1=app.make_packet('S1',1,'NORTH',now,'FIRE',4,'north one')
            p2=app.make_packet('S1',2,'NORTH',now,'FIRE',7,'north two')
            p3=app.make_packet('S2',1,'NORTH',now,'WIND',3,'north three')
            self.assertEqual(set(p1)-{'signature'},set(app.signed_fields(p1)))
            server=m.ReceiverServer(app,0)
            try:
                for packet in (p1,p2,p3):
                    self.assertTrue(m.send_raw(m.frame_bytes(packet),server.port).startswith('ACCEPTED'))
                self.assertIn('Replay',m.send_raw(m.frame_bytes(p1),server.port))
                for raw in (b'x\n{}',b'0\n',b'10\n{}',b'2\n{!',b'2\n{}extra'):
                    self.assertTrue(m.send_raw(raw,server.port).startswith('REJECTED'),raw)
                changed=dict(p2);changed['group']='OTHER';changed['sequence']=3;changed['packet_id']='S1:3'
                self.assertTrue(m.send_raw(m.frame_bytes(changed),server.port).startswith('REJECTED'))
                unknown=dict(p1);unknown['entity_id']='UNKNOWN';unknown['packet_id']='UNKNOWN:1'
                self.assertTrue(m.send_raw(m.frame_bytes(unknown),server.port).startswith('REJECTED'))
                missing=dict(p1);missing.pop('wrapped_key')
                self.assertTrue(m.send_raw(m.frame_bytes(missing),server.port).startswith('REJECTED'))
                bad_wrap=app.make_packet('S1',3,'NORTH',now,'FIRE',1,'bad wrap')
                bad_wrap['wrapped_key']='00'
                bad_wrap['signature']=app.sign(app.signed_fields(bad_wrap),m.load_private(app._entity_private_path('S1')))
                self.assertTrue(m.send_raw(m.frame_bytes(bad_wrap),server.port).startswith('REJECTED'))
            finally:server.close()
            self.assertEqual(len(app.events()),3)
            with patch.object(app,'_decrypt_packet_note',wraps=app._decrypt_packet_note) as decrypt_rejected:
                with self.assertRaisesRegex(ValueError,'Replay'):app.accept_packet(p1)
                invalid=dict(p2);invalid['group']='SOUTH';invalid['sequence']=3;invalid['packet_id']='S1:3'
                with self.assertRaisesRegex(ValueError,'signature'):app.accept_packet(invalid)
                decrypt_rejected.assert_not_called()
            with self.assertRaisesRegex(ValueError,'bounded'):app.make_packet('S1',3,'NORTH',now,'FIRE',1_000_000_000_001,'too large')
            self.assertEqual([x['packet_id'] for x in app.search(' fire ')],['S1:1','S1:2'])
            self.assertEqual(app.decrypt_note('S1:1'),'north one')
            with patch.object(m,'paillier_decrypt',wraps=m.paillier_decrypt) as decrypt:
                total=app.aggregate(['S1:1','S1:2','S2:1'],'NORTH')
                self.assertEqual(total['final_total'],14)
                self.assertEqual(decrypt.call_count,1)
            with self.assertRaisesRegex(ValueError,'distinct'):app.aggregate(['S1:1','S1:1'],'NORTH')
            with self.assertRaisesRegex(ValueError,'Mixed-group'):app.aggregate(['S1:1'],'SOUTH')
            with self.assertRaisesRegex(ValueError,'Unknown Packet'):app.aggregate(['MISSING'],'NORTH')
            restarted=m.NetworkRecords(data);restarted.setup_keys()
            self.assertEqual(restarted.decrypt_note('S1:2'),'north two')
            self.assertEqual(restarted.aggregate(['S1:1','S1:2','S2:1'],'NORTH')['final_total'],14)
            restarted.config['max_count']=restarted.pub['n']
            with self.assertRaisesRegex(ValueError,'wrap'):restarted.aggregate(['S1:1'],'NORTH')
            rows=json.loads((data/'accepted_events.json').read_text(encoding='utf-8'))
            rows[0]['packet']['group']='SOUTH'
            (data/'accepted_events.json').write_text(json.dumps(rows),encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'hash chain'):restarted.decrypt_note('S1:1')
            rows=json.loads((data/'accepted_events.json').read_text(encoding='utf-8'))
            rows[0]['packet']['group']='NORTH'
            rows[0]['search_token']='00'
            previous='0'*64
            for event in rows:
                event['prev_hash']=previous
                event['event_hash']=m.sha256(m.canonical({k:event[k] for k in ('packet','search_token','prev_hash')}))
                previous=event['event_hash']
            (data/'accepted_events.json').write_text(json.dumps(rows),encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'search token'):restarted.search('FIRE')

    def test_other_aes_sha_and_option_conflicts(self):
        with tempfile.TemporaryDirectory() as d:
            options=self.sensor_options();options.update(aes_bits=128,hash_name='sha512',hmac_hash='sha512')
            _,_,_,validation,module=generated(d,options)
            self.assertIn('functional self-test PASSED',validation)
            self.assertEqual(module.CONFIG['aes_bits'],128)
            custom=dict(options)
            custom['roles']=['Coordinator','Device','Inspector']
            custom['role_actions']={'Coordinator':[1,2,4],'Device':[3],'Inspector':[5,6,7]}
            _,_,_,custom_validation,custom_module=generated(d,custom)
            self.assertIn('functional self-test PASSED',custom_validation)
            self.assertEqual(custom_module.CONFIG['role_actions']['Inspector'],[5,6,7])
            with self.assertRaisesRegex(ValueError,'AES-GCM bits'):builder.network_options({'aes_bits':64})
            with self.assertRaisesRegex(ValueError,'operation map'):builder.network_options({'roles':['A','B','C']})
            with self.assertRaisesRegex(ValueError,'Network workflow cannot'):builder.normalize({'tcp_framed','md5'})
            with self.assertRaisesRegex(ValueError,'Unknown local-record setting'):builder.build('6',{'sha256'},options)

if __name__=='__main__':unittest.main()
