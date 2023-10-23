from ldap3 import Server, Connection ,ALL


server=Server('10.253.251.100',get_info=ALL)
print('kkkk')
a=False
try:
    conn=Connection(server,'user.root@ufnt.local','@Aa1020')
    print(conn.bind())
    a=True
except:
    print(f'erro:')
    a='offline'

if a == 'offline':
    print('offline LDAP')
elif a:
    print('login')
else:
    print('não login')



