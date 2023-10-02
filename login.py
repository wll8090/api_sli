from ldap3 import Server, Connection ,ALL


server=Server('10.253.251.13',get_info=ALL)
conn=Connection(server,'user.root@ufnt.local','@Aa1020')

print(conn.bind())

'''filter=f'(&(objectClass=user)(division=12345678909))'
attri=['cn','division']
conn.search('DC=ufnt,DC=local',filter,attributes=attri)
for i in conn.entries:
    print(i,end=('-'*30)+'\n')'''

