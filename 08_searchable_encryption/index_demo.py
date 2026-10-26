"""Lab 8 keyed-token inverted index demo, not formal SSE/PKSE."""
import hashlib,hmac,secrets,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import aes_encrypt,aes_decrypt
def token(key,word):return hmac.new(key,word.casefold().strip().encode(),hashlib.sha256).hexdigest()
def make_index(documents,key):
    index={}
    for doc_id,text in documents.items():
        for word in set(text.casefold().split()):index.setdefault(token(key,word),[]).append(doc_id)
    return index
def search(index,key,word):return index.get(token(key,word),[])
if __name__=='__main__':
    docs={f'D{i}':f'patient record {i} treatment '+('glucose' if i%2 else 'cardiac') for i in range(10)}
    index_key=secrets.token_bytes(32);data_key=secrets.token_bytes(32)
    idx=make_index(docs,index_key);encrypted={id:aes_encrypt(text.encode(),data_key) for id,text in docs.items()}
    hits=search(idx,index_key,input('Keyword: '))
    print('Ten AES-encrypted documents indexed. Query IDs:',hits)
    print('Authorized client decrypted matches:',{id:aes_decrypt(encrypted[id],data_key).decode() for id in hits})
    print('Index tokens hide literal words but leak repeated queries, matching IDs and counts.')
