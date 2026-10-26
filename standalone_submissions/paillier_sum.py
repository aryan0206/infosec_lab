"""Standalone sum template. Requires cryptography; pure Paillier arithmetic below."""
import math,secrets
from cryptography.hazmat.primitives.asymmetric import rsa
def setup():
    z=rsa.generate_private_key(public_exponent=65537,key_size=1024).private_numbers()
    n=z.p*z.q; lam=math.lcm(z.p-1,z.q-1)
    return n,lam,pow(lam,-1,n)
def encrypt(m,n):
    if not 0<=m<n: raise ValueError('number must be 0..n-1')
    while True:
        r=secrets.randbelow(n-1)+1
        if math.gcd(r,n)==1: break
    return pow(n+1,m,n*n)*pow(r,n,n*n)%(n*n)
def add_encrypted(items,n):
    result=1
    for c in items: result=result*c%(n*n)
    return result
def decrypt(c,n,lam,mu): return ((pow(c,lam,n*n)-1)//n)*mu%n
def main():
    n,lam,mu=setup()
    while True:
        print('\n1. Encrypt and sum integer list  0. Exit')
        choice=input('Choice: ').strip()
        if choice=='0': return
        if choice!='1': print('Invalid option.'); continue
        try:
            values=[int(x.strip()) for x in input('Nonnegative integers, comma-separated: ').split(',')]
            if not values or any(v<0 for v in values) or sum(values)>=n: raise ValueError('Invalid values or sum wraps modulus')
            ciphertexts=[encrypt(v,n) for v in values]
            combined=add_encrypted(ciphertexts,n)
            print('Ciphertexts:',ciphertexts,'\nCombined ciphertext:',combined)
            print('Final decrypted sum:',decrypt(combined,n,lam,mu),'expected:',sum(values))
        except ValueError as exc: print('Input error:',exc)
if __name__=='__main__': main()
