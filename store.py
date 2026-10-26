"""Small JSON persistence helpers. Local exam demonstration, not secure key custody."""
import json
from pathlib import Path
from core import encode_bytes, decode_bytes, format_version, rsa_keypair, save_private, load_private, paillier_keypair
import secrets

def read_json(path, default):
    path=Path(path)
    if not path.exists(): return default
    try: return json.loads(path.read_text(encoding='utf-8'))
    except (OSError,json.JSONDecodeError) as exc: raise ValueError(f'Malformed stored file {path}: {exc}') from exc

def write_json(path,value):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_suffix(path.suffix+'.tmp')
    temp.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    temp.replace(path)

def demo_keys(directory, rsa_bits=2048):
    directory=Path(directory); directory.mkdir(parents=True,exist_ok=True)
    path=directory/'keys.json'; pem=directory/'rsa_private.pem'
    if path.exists()!=pem.exists(): raise ValueError('Incomplete key state; restore both files or reset demo data')
    if not path.exists():
        public,private=paillier_keypair()
        write_json(path,{'format_version':2,'aes':encode_bytes(secrets.token_bytes(24),2),'paillier_public':public,'paillier_private':private})
        save_private(pem,rsa_keypair(rsa_bits))
    state=read_json(path,{})
    return decode_bytes(state['aes'],format_version(state)),load_private(pem),state['paillier_public'],state['paillier_private']

def paillier_public(state): return {k:int(v) for k,v in state.items()}
def paillier_private(state): return {k:int(v) for k,v in state.items()}
