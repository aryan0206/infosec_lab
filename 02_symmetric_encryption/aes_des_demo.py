"""Manual Lab 2: AES, DES-equivalent and 3DES CBC round trips/timing."""
import secrets,time
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
def roundtrip(label,algorithm,data):
    block=algorithm.block_size;iv=secrets.token_bytes(block//8)
    pad=padding.PKCS7(block).padder();padded=pad.update(data)+pad.finalize()
    start=time.perf_counter();enc=Cipher(algorithm,modes.CBC(iv)).encryptor();cipher=enc.update(padded)+enc.finalize();enc_time=time.perf_counter()-start
    start=time.perf_counter();dec=Cipher(algorithm,modes.CBC(iv)).decryptor();plain=dec.update(cipher)+dec.finalize();unpad=padding.PKCS7(block).unpadder();plain=unpad.update(plain)+unpad.finalize();dec_time=time.perf_counter()-start
    print(label,'ciphertext hex:',cipher.hex(),'roundtrip:',plain==data,'encrypt seconds:',enc_time,'decrypt seconds:',dec_time)
if __name__=='__main__':
    data=input('Message: ').encode()
    roundtrip('AES-128',algorithms.AES(secrets.token_bytes(16)),data)
    roundtrip('AES-256',algorithms.AES(secrets.token_bytes(32)),data)
    k=secrets.token_bytes(8)
    roundtrip('DES-equivalent EDE with K,K,K; historical only',TripleDES(k*3),data)
    roundtrip('3DES; historical only',TripleDES(secrets.token_bytes(24)),data)
