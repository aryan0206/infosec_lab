"""Manual Lab 1 demonstrations. Letters A-Z only; punctuation/spaces are discarded."""
import math
def clean(text):return ''.join(c for c in text.upper() if 'A'<=c<='Z')
def affine(text,a,b,decrypt=False):
    if math.gcd(a,26)!=1:raise ValueError('a must be coprime to 26')
    f=(lambda x:pow(a,-1,26)*(x-b)%26) if decrypt else (lambda x:(a*x+b)%26)
    return ''.join(chr(65+f(ord(c)-65)) for c in clean(text))
def vigenere(text,key,decrypt=False):
    key=clean(key)
    if not key:raise ValueError('Nonempty alphabetic keyword required')
    sign=-1 if decrypt else 1
    return ''.join(chr(65+(ord(c)-65+sign*(ord(key[i%len(key)])-65))%26) for i,c in enumerate(clean(text)))
def rail_fence(text,rails,decrypt=False):
    text=clean(text)
    if rails<2:raise ValueError('At least two rails required')
    route=[];row=0;step=1
    for _ in text:
        route.append(row)
        if row==0:step=1
        if row==rails-1:step=-1
        row+=step
    if not decrypt:return ''.join(text[i] for r in range(rails) for i in range(len(text)) if route[i]==r)
    order=[i for r in range(rails) for i in range(len(text)) if route[i]==r]
    result=['']*len(text)
    for char,i in zip(text,order):result[i]=char
    return ''.join(result)
def autokey(text,key,decrypt=False):
    if not 0<=key<26:raise ValueError('initial key must be 0..25')
    letters=clean(text);output=[];prior=key
    for ch in letters:
        x=ord(ch)-65;y=(x-prior)%26 if decrypt else (x+prior)%26
        output.append(chr(65+y));prior=y if decrypt else x
    return ''.join(output)
def playfair(text,key,decrypt=False):
    alphabet='ABCDEFGHIKLMNOPQRSTUVWXYZ';seen=''
    for c in clean(key).replace('J','I')+alphabet:
        if c not in seen:seen+=c
    positions={c:divmod(i,5) for i,c in enumerate(seen)}
    letters=clean(text).replace('J','I')
    if not decrypt:
        pairs=[];i=0
        while i<len(letters):
            a=letters[i];b=letters[i+1] if i+1<len(letters) else 'X'
            if a==b:b='X' if a!='X' else 'Q';i+=1
            else:i+=2
            pairs.append((a,b))
    else:
        if len(letters)%2:raise ValueError('Playfair ciphertext length must be even')
        pairs=list(zip(letters[::2],letters[1::2]))
    shift=-1 if decrypt else 1;out=[]
    for a,b in pairs:
        ra,ca=positions[a];rb,cb=positions[b]
        if ra==rb:out.extend((seen[ra*5+(ca+shift)%5],seen[rb*5+(cb+shift)%5]))
        elif ca==cb:out.extend((seen[((ra+shift)%5)*5+ca],seen[((rb+shift)%5)*5+cb]))
        else:out.extend((seen[ra*5+cb],seen[rb*5+ca]))
    return ''.join(out)  # Decrypt retains filler X/Q; caller removes only when justified.
def hill2(text,key,decrypt=False):
    if len(key)!=4:raise ValueError('2x2 key requires four integers')
    a,b,c,d=key;det=(a*d-b*c)%26
    if math.gcd(det,26)!=1:raise ValueError('Hill key determinant has no inverse mod 26')
    if decrypt:
        inv=pow(det,-1,26);a,b,c,d=(d*inv)%26,(-b*inv)%26,(-c*inv)%26,(a*inv)%26
    letters=clean(text)
    if len(letters)%2:letters+='X'
    out=''
    for x,y in zip(letters[::2],letters[1::2]):
        u,v=ord(x)-65,ord(y)-65;out+=chr(65+(a*u+b*v)%26)+chr(65+(c*u+d*v)%26)
    return out
if __name__=='__main__':
    print('Affine HELLO:',affine('HELLO',5,8),'->',affine(affine('HELLO',5,8),5,8,True))
    print('Vigenere:',vigenere('LIFEISFULLOFSURPRISES','HEALTH'))
    print('Rail fence:',rail_fence('INFORMATIONSECURITY',3))
    print('Autokey:',autokey('HELLO',7))
    print('Playfair:',playfair('HIDE THE GOLD','MONARCHY'))
    print('Hill:',hill2('HELP',(3,3,2,5)))
