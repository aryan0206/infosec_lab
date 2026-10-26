"""Manual Lab 6: sign exact bytes, verify, then demonstrate tampering."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import rsa_keypair,rsa_sign,rsa_verify,elgamal_keypair,elgamal_sign_digest,elgamal_verify_digest
import hashlib
if __name__=='__main__':
    data=input('Document: ').encode();key=rsa_keypair();signature=rsa_sign(data,key)
    print('RSA valid:',rsa_verify(data,signature,key.public_key()))
    print('Modified valid:',rsa_verify(data+b'!',signature,key.public_key()))
    public,private=elgamal_keypair();digest=hashlib.sha512(data).digest();sig=elgamal_sign_digest(digest,public,private)
    print('Toy ElGamal valid:',elgamal_verify_digest(digest,sig,public))
