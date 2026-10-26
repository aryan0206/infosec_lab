"""Reusable educational cryptographic blocks. Never deploy as a security service."""
import base64
import hashlib
import json
import math
import secrets
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as asympad, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key, load_pem_public_key

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def b64(data): return base64.b64encode(data).decode('ascii')
def unb64(data): return base64.b64decode(data, validate=True)

def format_version(record):
    if 'format_version' not in record:return 1
    if type(record['format_version']) is not int or record['format_version']!=2:raise ValueError('Unsupported format version')
    return 2

def encode_bytes(data,version):
    if version==1:return b64(data)
    if version==2:return data.hex()
    raise ValueError('Unsupported format version')

def decode_bytes(value,version):
    if not isinstance(value,str):raise ValueError('Encoded bytes must be text')
    if version==1:return unb64(value)
    if version==2:
        if len(value)%2 or any(ch not in '0123456789abcdef' for ch in value):raise ValueError('Malformed lowercase hex bytes')
        return bytes.fromhex(value)
    raise ValueError('Unsupported format version')

def encode_integer(value,version):
    if version==1:return str(value)
    if version==2:return hex(value)
    raise ValueError('Unsupported format version')

def decode_integer(value,version):
    if not isinstance(value,str):raise ValueError('Encoded integer must be text')
    if version==1:return int(value)
    if version==2:
        if not value.startswith('0x') or not value[2:] or any(ch not in '0123456789abcdef' for ch in value[2:]):raise ValueError('Malformed lowercase hex integer')
        return int(value,16)
    raise ValueError('Unsupported format version')

def encode_blob(blob,version):
    return {name:encode_bytes(unb64(value),version) for name,value in blob.items()}

def decode_blob(blob,version):
    return {name:b64(decode_bytes(value,version)) for name,value in blob.items()}
def sha256(data): return hashlib.sha256(data).hexdigest()
def sha512(data): return hashlib.sha512(data).hexdigest()
def md5(data): return hashlib.md5(data).hexdigest()  # Question C only; collision-unsafe.

def aes_encrypt(data, key):
    if len(key) not in (16, 24, 32): raise ValueError('AES key must be 16, 24, or 32 bytes')
    nonce=secrets.token_bytes(12)
    return {'nonce':b64(nonce),'ciphertext':b64(AESGCM(key).encrypt(nonce,data,None))}

def aes_decrypt(blob,key):
    return AESGCM(key).decrypt(unb64(blob['nonce']),unb64(blob['ciphertext']),None)

def aes_encrypt_record(data,key,version):return encode_blob(aes_encrypt(data,key),version)
def aes_decrypt_record(blob,key,version):return aes_decrypt(decode_blob(blob,version),key)

def cbc_encrypt(data,key):
    if len(key)!=32: raise ValueError('AES-256-CBC needs a 32-byte key')
    iv=secrets.token_bytes(16)
    padder=padding.PKCS7(128).padder(); padded=padder.update(data)+padder.finalize()
    enc=Cipher(algorithms.AES(key),modes.CBC(iv)).encryptor()
    return {'iv':b64(iv),'ciphertext':b64(enc.update(padded)+enc.finalize())}

def cbc_decrypt(blob,key):
    dec=Cipher(algorithms.AES(key),modes.CBC(unb64(blob['iv']))).decryptor()
    padded=dec.update(unb64(blob['ciphertext']))+dec.finalize()
    unpad=padding.PKCS7(128).unpadder(); return unpad.update(padded)+unpad.finalize()

def cbc_encrypt_record(data,key,version):return encode_blob(cbc_encrypt(data,key),version)
def cbc_decrypt_record(blob,key,version):return cbc_decrypt(decode_blob(blob,version),key)

def rsa_keypair(bits=2048):
    return rsa.generate_private_key(public_exponent=65537,key_size=bits)

def rsa_sign(data,private):
    return b64(private.sign(data,asympad.PSS(mgf=asympad.MGF1(hashes.SHA256()),salt_length=asympad.PSS.MAX_LENGTH),hashes.SHA256()))

def rsa_verify(data,signature,public):
    try: public.verify(unb64(signature),data,asympad.PSS(mgf=asympad.MGF1(hashes.SHA256()),salt_length=asympad.PSS.MAX_LENGTH),hashes.SHA256()); return True
    except (InvalidSignature,ValueError): return False

def rsa_sign_record(data,private,version):return encode_bytes(unb64(rsa_sign(data,private)),version)
def rsa_verify_record(data,signature,public,version):
    try:return rsa_verify(data,b64(decode_bytes(signature,version)),public)
    except (TypeError,ValueError):return False

def rsa_wrap(key,public): return b64(public.encrypt(key,asympad.OAEP(mgf=asympad.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None)))
def rsa_unwrap(blob,private): return private.decrypt(unb64(blob),asympad.OAEP(mgf=asympad.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
def rsa_wrap_record(key,public,version):return encode_bytes(unb64(rsa_wrap(key,public)),version)
def rsa_unwrap_record(blob,private,version):return rsa_unwrap(b64(decode_bytes(blob,version)),private)

def save_private(path,key): path.write_bytes(key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
def save_public(path,key): path.write_bytes(key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
def load_private(path): return load_pem_private_key(path.read_bytes(),password=None)
def load_public(path): return load_pem_public_key(path.read_bytes())

def rsa_textbook_parameters(p,q,e):
    if p==q or p<3 or q<3 or not is_prime(p) or not is_prime(q): raise ValueError('distinct prime p,q required')
    phi=(p-1)*(q-1)
    if e<=1 or e>=phi or math.gcd(e,phi)!=1: raise ValueError('e must be in 2..phi-1 and coprime to phi')
    return p*q,e,pow(e,-1,phi)

def is_prime(n):
    if n<2:return False
    for d in range(2,math.isqrt(n)+1):
        if n%d==0:return False
    return True

def rsa_multiply_encrypted(c1,c2,n):
    if not 0<=c1<n or not 0<=c2<n: raise ValueError('ciphertext out of range')
    return (c1*c2)%n

def rsa_product(a,b,n,e,d):
    if type(n) is not int or type(e) is not int or type(d) is not int or n<4 or e<=1 or d<=1:
        raise ValueError('invalid RSA modulus or exponents')
    if not (1<=a<n and 1<=b<n): raise ValueError('both inputs must be 1..N-1')
    c1,c2=pow(a,e,n),pow(b,e,n)
    if pow(c1,d,n)!=a or pow(c2,d,n)!=b:
        raise ValueError('private exponent does not decrypt the entered inputs')
    combined=rsa_multiply_encrypted(c1,c2,n)
    result=pow(combined,d,n)
    modular_verified=result==(a*b)%n
    ordinary_verified=result==a*b
    return {'ciphertexts':[c1,c2],'combined':combined,'decrypted':result,
            'expected_mod_n':(a*b)%n,'ordinary_product':a*b,
            'modular_verified':modular_verified,'ordinary_verified':ordinary_verified,
            'verified':ordinary_verified,'no_wrap':a*b<n}

def paillier_keypair(bits=1024):
    if bits<1024: raise ValueError('use at least 1024-bit demo modulus')
    nums=rsa_keypair(bits).private_numbers(); p,q=nums.p,nums.q
    n=p*q; lam=math.lcm(p-1,q-1); mu=pow(lam,-1,n)
    return {'n':n,'g':n+1},{'lambda':lam,'mu':mu}

def paillier_encrypt(m,pub):
    n=pub['n']
    if type(m) is not int or not 0<=m<n: raise ValueError('Paillier message must be integer in 0..n-1')
    while True:
        r=secrets.randbelow(n-1)+1
        if math.gcd(r,n)==1: break
    return (pow(pub['g'],m,n*n)*pow(r,n,n*n))%(n*n)

def paillier_add(ciphertexts,pub):
    n2=pub['n']**2; result=1
    for c in ciphertexts:
        if type(c) is not int or not 1<=c<n2 or math.gcd(c,pub['n'])!=1: raise ValueError('invalid Paillier ciphertext')
        result=result*c%n2
    return result

def paillier_decrypt(c,pub,priv):
    n=pub['n']; n2=n*n
    if type(c) is not int or not 1<=c<n2 or math.gcd(c,n)!=1: raise ValueError('invalid Paillier ciphertext')
    return (((pow(c,priv['lambda'],n2)-1)//n)*priv['mu'])%n

# Small explicit group for an educational ElGamal signature, never a real voter identity.
ELGAMAL_P=467; ELGAMAL_G=2
def elgamal_keypair():
    x=secrets.randbelow(ELGAMAL_P-3)+2
    return {'p':ELGAMAL_P,'g':ELGAMAL_G,'y':pow(ELGAMAL_G,x,ELGAMAL_P)},x

def elgamal_sign_digest(digest,public,x):
    p=public['p']; h=int.from_bytes(digest,'big')%(p-1)
    while True:
        k=secrets.randbelow(p-2)+1
        if math.gcd(k,p-1)==1: break
    r=pow(public['g'],k,p); s=((h-x*r)*pow(k,-1,p-1))%(p-1)
    return {'r':r,'s':s}

def elgamal_verify_digest(digest,signature,public):
    try:
        p,g,y=public['p'],public['g'],public['y']; r,s=signature['r'],signature['s']
        return 1<=r<p and 0<=s<p-1 and pow(g,int.from_bytes(digest,'big')%(p-1),p)==pow(y,r,p)*pow(r,s,p)%p
    except (KeyError,TypeError,ValueError): return False
