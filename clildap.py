from ldap3 import Server, Connection, ALL, SUBTREE , MODIFY_ADD , MODIFY_DELETE, MODIFY_REPLACE
import subprocess as sub
from hashlib import sha256
from random import randint
from json import loads
from datetime import datetime
from random import randint
from seed_email import enviar_email

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
        return {'response':self.conn.bind()}
    
    def logout(self):
        self.conn.unbind()
        return {'response':True}
    
    def my_dados(self):
        self.conn.search(f'{base}',
                        f'(&(objectclass=user)(sAMAccountName={self.user}))' ,
                        attributes=['cn','sAMAccountName','distinguishedName','memberof','telephoneNumber',
                                    'mail','givenname','info'],
                        search_scope=SUBTREE)
        i=self.conn.entries[0]
        self.all_dados={'user':valid(f'{i.cn}'),
                        'givenname': valid(f'{i.givenname}'),
                        'memberof': valid(f'{i.memberof}'),
                        'sAMAccountName': valid(f'{i.sAMAccountName}'),
                        'mail2': valid(f'{i.mail}'),
                        'mail': valid(f'{i.sAMAccountName}')+dominio,
                        'token':self.userID,
                        'DN': f'{i.distinguishedName}',
                        'telefone':f'{i.telephoneNumber}',
                        'info':f'{i.info}'}
        return self.all_dados
    
    def consulta(self,nome,quant_pag=20):
        text=f'(&(objectclass=user)(cn={nome}*))'
        ll=['displayname','cn','givenname','mail','telephonenumber','objectclass','memberof',
            'distinguishedName','info','sAMAccountName','userAccountControl','telephoneNumber']
        self.conn.search(base, text ,attributes=ll)
        dados={}
        cont=1
        for n,i in enumerate(self.conn.entries):
            if n%quant_pag==0:
                NL=f'users{cont:0>3}'
                dados.update({NL:[]})
                pag=dados[NL]
                cont+=1
            pag.append({'cn':f'{i.cn}'.replace("[]",''),
                        'givenname': f'{i.givenname}'.replace("[]",''),
                        'memberof': f'{i.memberof}'.replace("[]",''),
                        'telephonenumber': f'{i.telephonenumber}'.replace("[]",''),
                        'mail': f'{i.mail}'.replace("[]",''),
                        'givenname': f'{i.givenname}'.replace("[]",''),
                        'DN': f'{i.distinguishedName}',
                        'info':f'{i.info}',
                        'login':f'{i.sAMAccountName}',
                        'telefone':f'{i.telephoneNumber}',
                        'estado':i.userAccountControl.value & 2 != 2})
        return dados

    def validar_objeto(self,attr,valor):
        filter=f'(&(objectClass=user)({attr}={valor}))'
        attri=[attr]
        self.conn.search(base,filter,attributes=attri)
        return(bool(self.conn.entries))
    
    def adduser(self,dados:dict) ->dict :   #adiciona usuario  
        nome=dados['nome']                  # dados é um json
        l_nome=nome.split()
        fn=l_nome[0]
        ln=' '.join(l_nome[1:])
        login1=login=f'{fn}.{l_nome[-1]}'.lower()
        login2=f'{fn}.{[l_nome[-3],l_nome[-2]][len(l_nome[-2])>2]}'.lower()

        if self.validar_objeto('cn',nome):  #verificação de usuario
            return {'response':False,'mensg':'usuario ja existe','login':f'{login1}'}
        if self.validar_objeto('sAMAccountName',login):  #verificação de login1
            login=login2
            if self.validar_objeto('sAMAccountName',login): #verificação de login2
                return {'response':False,'mensg':'login ja existe','login':f'{login1} & {login2}'}

        DN=f"CN={nome},CN=Users,{base}"
        attr={  'objectclass':['top','person', 'organizationalPerson', 'user'],
                'cn':nome,                                      #nome completo
                'displayname':nome,                             #nome completo
                'uid':login,                                    #idetificador unico
                'givenName':l_nome[0],                          #primeiro nome
                'sn':' '.join(l_nome[1:]),                      #sobre nome
                'sAMAccountName':login,                         #login
                'description':dados["desc"],                    #descrição da conta
                'mail':dados.get('email2'),                     #email segundario
                'userPrincipalName':f'{login}{dominio}',        #email de login do ldap
                'userAccountControl':'66080',                   #estado da conta
                'info':f"criador: {self.all_dados['DN']}",      #informação do criador
                'telephoneNumber':f'{dados.get("telefone")}'}
        
        add_aluno =grupos.get("ADD_ALUNO") 
        add_servidor =grupos.get("ADD_SERVIDOR") 
        if add_aluno in self.all_dados['memberof']:
            GP=grupos.get('ALUNO')
        elif add_servidor in self.all_dados['memberof']:
            GP=grupos.get('SERVIDOR')
        else:
            return {'response':False,'mensg':'sem autorização','login':'None'}
        r=self.conn.add(DN,attributes=attr)
        c=login
        b='usuario criado'
        if r:
            pwd=f'Senha@{randint(1000,9999)}'
            command=f'dsmod user "{DN}" -pwd "{pwd}" -mustchpwd no'
            a='passa sem shell'
            if shell:
                a=sub.run(command,shell=1,capture_output=1,text=1).stdout
            if a=='':
                b='erro no formato da senha'
                self.conn.delete(DN)
                r=False
        self.modify_group({'DN_user':DN,'DN_group':GP,'modify':'add'})  # adiciona no grupo segundo o cargo
        texto=f'''
Ola {nome}.

'''
        enviar_email(dados.get('email2'),'Senha de acesso')
        return {'response':r,'mensg':b,'login':c}
    
    def rm_user(self,dados):
        DN=dados.get('DN')
        if DN==self.all_dados["DN"]:
            return None
        self.conn.delete(DN)
        re=False
        msg='usuario não deletado'
        if self.conn.result['result']==0:
            re=True
            msg='usuario deletado'
        return {'response':re,'mensg':msg}

    def consulta_group(self,letra,quant_pag=20,membros=0):
        text=f'(&(objectclass=group)(cn={letra}*))'
        ll=['cn','distinguishedName','desktopProfile','description','info']
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
                    'desc': f'{i.description}',
                    'info':f'{i.info}'}
            if membros:
                dici['membros']=[j.split(',')[0].split('=')[1] for j in i.member]
            pag.append(dici)
        return dados

    def creat_group(self, dados):
        nome=dados['nome']
        if self.consulta_group(nome).get('group001'):
            return {'response':False,'mensg':'grupo ja existe'}
        dn=f'CN={nome},CN=users,{base}'
        desc=dados['desc']
        group={ 'objectclass':['top','group'],
                'cn':nome,
                'description':desc,
                'info':f"criador: {self.all_dados['DN']}"}
        re=self.conn.add(dn,attributes=group)
        return {'response':re,'mensg':'add grupo'}
    
    def modify_group(self,dados):
        user_dn=dados['DN_user']
        group_dn=dados['DN_group']
        acao={  'add': MODIFY_ADD,
                'remove': MODIFY_DELETE} [dados['modify']]
        add={'member' : [(acao, [user_dn])]}
        self.conn.modify(group_dn, add)
        re=False
        if self.conn.result['result']==0:
            re=True
        return {'response':re,'mensg':dados['modify']}

    def rm_group(self,dados):
        DN=dados['DN']
        self.conn.delete(DN)
        re=False
        msg='grupo não deletado'
        if self.conn.result['result']==0:
            re=True
            msg='grupo deletado'
        return {'response':re,'mensg':msg}
    
    def exec_pwd(slef, DN , new_pwd):
        command=f'dsmod user "{DN}" -pwd "{new_pwd}" -mustchpwd no'
        if shell:
            a=sub.run(command,shell=1,capture_output=1,text=1).stdout
            a=sub.run(command,shell=1,capture_output=1,text=1).stdout
            if a=='':
                return {'response':False , 'mensg':'nova senha invalida'}
        return {'response':True , 'mensg':'ok'}

    def troca_senha(self,dados):
        pwd=dados['pwd']
        new_pwd=dados['new_pwd']
        DN=self.all_dados['DN']
        con=Connection(self.server,self.logon,pwd)
        if not con.bind(): 
            return {'response':False , 'mensg':'senha antiga invalida'}
        return self.exec_pwd(DN,new_pwd)

    def user_senha(self,dados):
        DN=dados.get('DN')
        new_pwd=dados.get("new_pwd")
        if DN==self.all_dados['DN']:
            return {'response':False , 'mensg':'erro de user.DN'}
        return self.exec_pwd(DN,new_pwd)
    
    def modify_my_count(self,dados):
        tell=dados.get('tell')
        email=dados.get('email')
        token=dados.get('token')
        attr={}

        if tell:
            attr['telephoneNumber']=[(MODIFY_REPLACE,[tell])]
        if email:
            if not token:
                self.codico=f'UFNT-{randint(100,999)}'
                texto=open('confirmar_email.html').read()
                enviar_email(email,'validar email',texto.format(self.all_dados['user'].title(),self.codico))
                return {'response':True, 'mensg':f'verificar {email}'}
            elif token !='teste.15975369874123658' and token != self.codico :
                return {'response':False, 'mensg':f'codico invalido'}
            attr['mail']=[(MODIFY_REPLACE,[email])]
        self.conn.modify(self.all_dados['DN'],attr)
        if self.conn.result['result']==0:
            return {'response':True, 'mensg':'Dados atualizados'}
        return {'response':False, 'mensg':'erro'}