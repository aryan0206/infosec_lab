"""Manual Lab 5 custom hash and standard digest comparison."""
import hashlib,secrets,time
def lab_hash(text):
    value=5381
    for char in text:value=((value*33)+ord(char))&0xffffffff
    return value
def compare(count=50):
    if not 50<=count<=100:raise ValueError('Manual exercise requests 50..100 strings')
    dataset=[secrets.token_hex(20) for _ in range(count)]
    for algorithm in ('md5','sha1','sha256'):
        start=time.perf_counter();digests=[hashlib.new(algorithm,s.encode()).hexdigest() for s in dataset]
        print(algorithm,'elapsed seconds:',time.perf_counter()-start,'observed collisions:',len(digests)-len(set(digests)))
    print('No observed collision in a tiny sample does not establish collision resistance.')
if __name__=='__main__':print('Lab hash:',lab_hash(input('Text: ')));compare()
