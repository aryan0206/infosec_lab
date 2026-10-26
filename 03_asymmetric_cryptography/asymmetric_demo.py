"""Manual Lab 3 small integer ElGamal/Rabin and RSA-OAEP / EC hybrid examples."""
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec,padding,rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def elgamal_roundtrip(m,p=467,g=2):
    if not 0<=m<p:raise ValueError('message out of range')
    x=secrets.randbelow(p-3)+2;y=pow(g,x,p);k=secrets.randbelow(p-2)+1
    c1=pow(g,k,p);c2=m*pow(y,k,p)%p
    return (c1,c2),c2*pow(pow(c1,x,p),-1,p)%p
def rabin_roots(m,p=7,q=11):
    if p%4!=3 or q%4!=3 or p==q or not 0<=m<p*q:raise ValueError('Blum primes and in-range message required')
    n=p*q;c=m*m%n;rp=pow(c,(p+1)//4,p);rq=pow(c,(q+1)//4,q)
    return c,sorted({(a*q*pow(q,-1,p)+b*p*pow(p,-1,q))%n for a in (rp,-rp) for b in (rq,-rq)})
def rsa_oaep_roundtrip(data):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    scheme=padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
    c=key.public_key().encrypt(data,scheme);return c,key.decrypt(c,scheme)
def ec_hybrid_roundtrip(data):
    receiver=ec.generate_private_key(ec.SECP256R1());sender=ec.generate_private_key(ec.SECP256R1())
    shared=sender.exchange(ec.ECDH(),receiver.public_key())
    key=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'lab-demo').derive(shared)
    nonce=secrets.token_bytes(12);cipher=AESGCM(key).encrypt(nonce,data,None)
    receiver_shared=receiver.exchange(ec.ECDH(),sender.public_key())
    receiver_key=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'lab-demo').derive(receiver_shared)
    return cipher,AESGCM(receiver_key).decrypt(nonce,cipher,None)
if __name__=='__main__':
    print('ElGamal',elgamal_roundtrip(25))
    print('Rabin four roots:',rabin_roots(12),'-- encoding needed to choose original')
    print('RSA OAEP:',rsa_oaep_roundtrip(b'Asymmetric Encryption'))
    print('EC hybrid:',ec_hybrid_roundtrip(b'Secure Transactions'))
