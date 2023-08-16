from ldap3 import Server, Connection, ALL, SUBTREE , MODIFY_ADD , MODIFY_DELETE
import subprocess as sub
from hashlib import sha256
from random import randint
from json import loads
from datetime import datetime 

with open('config.ini') as arq:
    conf=loads(arq.read())
    arq.close()

host=conf.get('app_api').get('HOST_LDAP')
dominio=conf.get('app_api').get('DOMINIO')
base=conf.get('app_api').get('BASE')
tokem=conf.get('testes').get('FAKE_TOKEM')
val_tokem=conf.get('testes').get('VAL_TOKEM')
shell=conf.get('testes').get('SHELL')
grupos=conf.get('DN_grupos')




def valid(dd):
    return f'{dd}'.replace("[]",'')

class user_ldap:
    def __init__(self,user,pwd):
        self.user=user
        self.logon=f'{user}{dominio}'
        self.pwd=pwd
        self.chave=f'{randint(0,33**333)}'
        self.userID= sha256((user+self.chave).encode()).hexdigest() if val_tokem else tokem

    
    def log_login(self):
        data=datetime.now().strftime("%d_%m_%Y")
        hora=datetime.now().strftime("%H:%M")
        with open(f'./login/login_{data}.log','a') as arq:
            texto=f'''"{self.user}" acesso em {hora}\n'''
            arq.write(texto)
            arq.close()

    def connetc(self):
        self.server=Server(host,get_info=ALL) 
        self.conn=Connection(self.server,self.logon,self.pwd)
        return self.conn.bind()
    
    def logout(self):
        self.conn.unbind()
        return True
    
    def my_dados(self):
        self.conn.search(f'{base}',
                        f'(&(objectclass=user)(sAMAccountName={self.user}))' ,
                        attributes=['cn','sAMAccountName','distinguishedName','memberof','mail','givenname'],
                        search_scope=SUBTREE)
        i=self.conn.entries[0]
        self.all_dados={'user':valid(f'{i.cn}'),
                'givenname': valid(f'{i.givenname}'),
                'memberof': valid(f'{i.memberof}'),
                'sAMAccountName': valid(f'{i.sAMAccountName}'),
                'mail2': valid(f'{i.mail}'),
                'mail': valid(f'{i.sAMAccountName}')+dominio,
                'givenname': valid(f'{i.givenname}'),
                'token':self.userID,
                'DN': f'{i.distinguishedName}'
                }
        return self.all_dados
    
    def consulta(self,nome,quant_pag=20):
        text=f'(&(objectclass=user)(cn={nome}*))'
        ll=['displayname','cn','givenname','mail','telephonenumber','objectclass','memberof','distinguishedName']
        self.conn.search(base, text ,attributes=ll)
        dados={}
        cont=1
        for n,i in enumerate(self.conn.entries):
            if n%quant_pag==0:
                NL=f'users{cont:0>3}'
                dados.update({NL:[]})
                pag=dados[NL]
                cont+=1
            pag.append({
                'cn':f'{i.cn}'.replace("[]",''),
                'givenname': f'{i.givenname}'.replace("[]",''),
                'memberof': f'{i.memberof}'.replace("[]",''),
                'telephonenumber': f'{i.telephonenumber}'.replace("[]",''),
                'mail': f'{i.mail}'.replace("[]",''),
                'givenname': f'{i.givenname}'.replace("[]",''),
                'DN': f'{i.distinguishedName}'
                })
        return dados
    
    def adduser(self,dados:dict) ->dict :  #adiciona usuario  
        nome=dados['nome']      # dados é um json
        cargo=dados.get('cargo')
        l_nome=nome.split()
        fn=l_nome[0]
        ln=' '.join(l_nome[1:])
        login1=f'{fn}.{l_nome[-1]}'
        login2=f'{fn}.{[l_nome[-3],l_nome[-2]][len(l_nome[-2])>2]}'

        DN=f"CN={nome},CN=Users,{base}"
        attr={
            'objectclass':['top','person', 'organizationalPerson', 'user'],
            'cn':nome,
            'displayname':nome,
            'uid':login1,
            'givenName':l_nome[0],
            'sn':' '.join(l_nome[1:]),
            'sAMAccountName':login1,
            'description':dados["desc"],
            'mail':dados.get('email2'),
            'userPrincipalName':f'{login1}@ufnt.local',
            'userAccountControl':'66080' }
        r=self.conn.add(DN,attributes=attr)
        c=login1
        b='usuario criado'
        if self.conn.result['result']==19:
            c=login2
            attr.update({'userPrincipalName':f'{login2}@ufnt.local',
                        'uid':login2,
                        'sAMAccountName':login2,
                        })
            r=self.conn.add(DN,attributes=attr)
            if not r:
                c=f'{login1} & {c}'
                b='o login ja existe'
        if r:
            command=f'dsmod user "{DN}" -pwd "{dados["pwd"]}" -mustchpwd no'
            a='passa sem shell'

            if shell:
                a=sub.run(command,shell=1,capture_output=1,text=1).stdout
            if a=='':
                b='erro no formato da senha'
                self.conn.delete(DN)
                r=False
        if self.conn.result['result']==68:
            b='Usuario ja existe'
        GP=grupos.get(cargo)
        print(GP)
        self.modify_group({'DN_user':DN,'DN_group':GP,'modify':'add'})  # adiciona no grupo segundo o cargo
        response={'response':r,'mensg':b,'login':c}
        return response
    
    def rm_user(self,dados):
        DN=dados.get('DN')
        if DN==self.all_dados["DN"]:
            return None
        self.conn.delete(DN)
        if self.conn.result['result']==0:
            return True
        return False

    def consulta_group(self,letra,quant_pag=20,membros=0):
        text=f'(&(objectclass=group)(cn={letra}*))'
        ll=['cn','distinguishedName','desktopProfile']
        dados={}
        cont=1
        if membros:ll.append('member')
        self.conn.search(base, text ,attributes=ll)
        for n,i in enumerate(self.conn.entries):
            if n%quant_pag==0:
                NL=f'group{cont:0>3}'
                dados.update({NL:[]})
                pag=dados[NL]
                cont+=1
            ugp=valid(f'{i.desktopProfile}')
            dici={  'cn':valid(f'{i.cn}'),
                    'DN':f'{i.distinguishedName}',
                    'UGP':ugp.split()[-1] if ugp else ''}
            if membros:
                dici['membros']=[j.split(',')[0].split('=')[1] for j in i.member]
            pag.append(dici)
        return dados

    def creat_group(self, dados):
        nome=dados['nome']
        UGP=dados['UGP']
        dn=f'CN={nome},CN=users,{base}'
        desc='grupo de teste LDAP3'
        group={
            'objectclass':['top','group'],
            'cn':nome,
            'description':desc,
            'desktopProfile':f'UGP {UGP}',
            }
        r=self.conn.add(dn,attributes=group)
        return r
    
    def modify_group(self,dados):
        user_dn=dados['DN_user']
        group_dn=dados['DN_group']
        acao={  'add': MODIFY_ADD,
                'remove': MODIFY_DELETE} [dados['modify']]
        
        add={'member' : [(acao, [user_dn])]}
        self.conn.modify(group_dn, add)
        if self.conn.result['result']==0:
            return True
        return False

    def rm_group(self,dados):
        DN=dados['DN']
        self.conn.delete(DN)
        return self.conn.result['result']==0

    def troca_senha(self,dados):
        pwd=dados['pwd']
        new_pwd=dados['new_pwd']
        DN=self.all_dados['DN']
        con=Connection(self.server,self.logon,pwd)
        if not con.bind(): 
            return {'response':False , 'mensg':'senha antiga invalida'}
        command=f'dsmod user "{DN}" -pwd "{new_pwd}" -mustchpwd no'
        a='passa sem shell'
        if shell:
            a=sub.run(command,shell=1,capture_output=1,text=1).stdout
            a=sub.run(command,shell=1,capture_output=1,text=1).stdout
            pass
        if a=='':
            return {'response':False , 'mensg':'nova senha invalida'}
        return {'response':True , 'mensg':'ok'}

    def user_senha(self,dados):
        DN=dados.get('DN')
        new_pwd=dados.get("new_pwd")
        command=f'dsmod user "{DN}" -pwd "{new_pwd}" -mustchpwd no'
        a='passa sem shell'
        print(command)
        if shell:
            a=sub.run(command,shell=1,capture_output=1,text=1).stdout
            a=sub.run(command,shell=1,capture_output=1,text=1).stdout
            pass
        if a=='':
            return {'response':False , 'mensg':'nova senha invalida'}
        return {'response':True , 'mensg':'ok'}
        
        

