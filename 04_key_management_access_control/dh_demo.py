"""Manual Lab 4 toy DH and revocable role policy illustration."""
import secrets
def exchange(p=23,g=5):
    a=secrets.randbelow(p-3)+2;b=secrets.randbelow(p-3)+2
    A=pow(g,a,p);B=pow(g,b,p)
    return A,B,pow(B,a,p),pow(A,b,p)
class Roles:
    def __init__(self):self.roles={};self.revoked=set()
    def grant(self,user,role):self.roles[user]=role;self.revoked.discard(user)
    def revoke(self,user):self.revoked.add(user)
    def permitted(self,user,operation):
        return user not in self.revoked and operation in {'researcher':{'submit'},'reviewer':{'verify'},'finance':{'tally'}}.get(self.roles.get(user),set())
if __name__=='__main__':
    A,B,left,right=exchange();print('DH public values:',A,B,'shared equal:',left==right)
    roles=Roles();roles.grant('Ada','reviewer');print('Verify allowed:',roles.permitted('Ada','verify'));roles.revoke('Ada');print('After revocation:',roles.permitted('Ada','verify'))
