from ldap3 import Server, Connection ,ALL


server=Server('10.253.251.16',get_info=ALL)
conn=Connection(server,'user.root@ufnt.local','@Aa1020')

print(conn.bind())


