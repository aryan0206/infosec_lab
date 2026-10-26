"""Manual Lab 5 multipart socket hash: run server and client in separate terminals."""
import hashlib,socket,sys,os
HOST='127.0.0.1';PORT=int(os.environ.get('IS_LAB_HASH_PORT','51321'))
def server():
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind((HOST,PORT));listener.listen(1)
        print('Listening on',HOST,PORT,flush=True)
        conn,_=listener.accept()
        with conn:
            with conn.makefile('rb') as stream:
                length=int(stream.readline().strip())
                if not 0<=length<=1_000_000:raise ValueError('Invalid length')
                data=stream.read(length)
                if len(data)!=length:raise ValueError('Incomplete data')
            conn.sendall(hashlib.sha256(data).hexdigest().encode()+b'\n')
            print('Received bytes:',length,'SHA-256:',hashlib.sha256(data).hexdigest())
def client(tamper=False):
    parts=[input('Part 1: '),input('Part 2: ')];data=''.join(parts).encode()
    sent=(bytes([data[0]^1])+data[1:] if data else b'!') if tamper else data
    if tamper:print('Tampering demo: one byte changed before transmission; the client still hashes the original message.')
    with socket.create_connection((HOST,PORT),timeout=10) as conn:
        conn.sendall(str(len(sent)).encode()+b'\n'+sent);conn.shutdown(socket.SHUT_WR)
        remote=conn.makefile('rb').readline().strip().decode()
    local=hashlib.sha256(data).hexdigest();print('Local original SHA-256:',local,'Server received SHA-256:',remote,'Match:',local==remote)
if __name__=='__main__':
    if sys.argv[1:] == ['server']:server()
    elif sys.argv[1:] == ['client']:client()
    elif sys.argv[1:] == ['client','--tamper']:client(tamper=True)
    else:raise SystemExit('Usage: python socket_hash_demo.py server | client [--tamper]')
