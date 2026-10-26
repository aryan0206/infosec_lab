"""One-file Lab 7 ElGamal ciphertext multiplication; educational small-prime exercise."""
import math
import secrets

def is_prime(value):
    if value<2:return False
    return all(value%factor for factor in range(2,math.isqrt(value)+1))

def prime_factors(value):
    factors=set();factor=2
    while factor*factor<=value:
        if value%factor==0:
            factors.add(factor)
            while value%factor==0:value//=factor
        factor+=1
    if value>1:factors.add(value)
    return factors

def parameters(p,g,x=None):
    if not is_prime(p) or p<5:raise ValueError('p must be a prime at least 5')
    if not 2<=g<p or any(pow(g,(p-1)//factor,p)==1 for factor in prime_factors(p-1)):
        raise ValueError('g must generate the multiplicative group modulo p')
    if x is None:x=secrets.randbelow(p-3)+2
    if not 1<=x<=p-2:raise ValueError('private exponent x must be in 1..p-2')
    return p,g,x,pow(g,x,p)

def encrypt(message,p,g,y):
    if not 1<=message<p:raise ValueError('inputs must be in 1..p-1')
    k=secrets.randbelow(p-2)+1
    return pow(g,k,p),message*pow(y,k,p)%p

def multiply_ciphertexts(first,second,p):
    """Only encrypted pairs enter this function; no plaintext operands are used."""
    return first[0]*second[0]%p,first[1]*second[1]%p

def decrypt(ciphertext,p,x):
    shared=pow(ciphertext[0],x,p)
    return ciphertext[1]*pow(shared,-1,p)%p

def elgamal_product(a,b,p=467,g=2,x=None):
    p,g,x,y=parameters(p,g,x)
    first,second=encrypt(a,p,g,y),encrypt(b,p,g,y)
    combined=multiply_ciphertexts(first,second,p)
    result=decrypt(combined,p,x)
    return {'public_key':(p,g,y),'ciphertexts':[first,second],
            'encrypted_product':combined,'decrypted':result,'expected':a*b%p,
            'ordinary_product':a*b,'verified':result==a*b%p}

def pair_hex(pair):return '('+', '.join(hex(part) for part in pair)+')'

def main():
    key=None
    while True:
        print('\n1 Set ElGamal p,g,x  2 Multiply encrypted values  0 Exit')
        choice=input('Choice: ').strip()
        try:
            if choice=='0':return
            if choice=='1':
                p=int(input('Prime p: '));g=int(input('Generator g: '))
                entered=input('Private exponent x (blank = random): ').strip()
                key=parameters(p,g,int(entered) if entered else None)
                print('Public key (p, g, y):',tuple(hex(value) for value in (key[0],key[1],key[3])))
            elif choice=='2':
                if key is None:print('Set group parameters first.');continue
                a=int(input('First integer (1..p-1): '));b=int(input('Second integer (1..p-1): '))
                result=elgamal_product(a,b,key[0],key[1],key[2])
                print('Encrypted inputs (hex):',*[pair_hex(pair) for pair in result['ciphertexts']])
                print('Ciphertext-only product (hex):',pair_hex(result['encrypted_product']))
                print('Decrypted product modulo p:',result['decrypted'],'expected:',result['expected'])
                print('Modular homomorphic equality verified' if result['verified'] else 'Verification failed')
                if result['ordinary_product']>=key[0]:
                    print('Ordinary product wraps modulo p:',result['ordinary_product'])
                else:print('Ordinary product verified:',result['ordinary_product'])
            else:print('Invalid option.')
        except ValueError as exc:print('Input error:',exc)

if __name__=='__main__':main()
