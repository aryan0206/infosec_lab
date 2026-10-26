"""Manual Lab 7: run RSA product, Paillier sum and ElGamal product examples."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import *
from standalone_submissions.elgamal_product import elgamal_product
if __name__=='__main__':
    n,e,d=rsa_textbook_parameters(5,11,3);print('RSA',rsa_product(2,3,n,e,d))
    public,private=paillier_keypair();items=[paillier_encrypt(v,public) for v in (15,25)]
    total=paillier_add(items,public);print('Paillier ciphertexts:',items,'encrypted sum:',total,'decrypted final:',paillier_decrypt(total,public,private))
    print('ElGamal',elgamal_product(3,7))
