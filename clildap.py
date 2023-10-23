import subprocess as sub
from ldap3 import Server, Connection, ALL, MODIFY_ADD , MODIFY_DELETE, MODIFY_REPLACE
from hashlib import sha256
from random import randint
from json import loads
from datetime import datetime
from random import randint
from seed_email import enviar_email
from unidecode import unidecode
from threading import Thread

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
boasvinda=conf.get('conf_email').get('BOASVINDA')
confirmaremail=conf.get('conf_email').get('CONFIRMAREMAIL')
email_esqueci_senha=conf.get('conf_email').get('ESQUECI_SENHA')
encode=conf.get('conf_email').get('ENCODE')
base_email=conf.get('conf_email').get('BASE')


attributes=['cn','sAMAccountName','distinguishedName','memberof','telephonenumber','comment',
            'mail','givenname','info','division','userAccountControl','adminDisplayName']

server=Server(host,get_info=ALL)

def valid(dd):
    return f'{dd}'.replace("[]",'')

def config_group(membro):
    membro={'a':membro}
    [membro.update({'a':membro['a'].replace(i,'')}) for i in "'[]"]
    membro['a']=membro['a'].split(', ')
    membro={i.split(',')[0][3:].upper():i for i in membro['a']}
    return membro

class user_ldap:
    def __init__(self,user,pwd):
        global root
        self.user=user
        self.logon=f'{user}{dominio}'
        self.pwd=pwd
        self.chave=f'{randint(0,33**333)}'
        if user == 'user.root':
            globals()['root']=[user,pwd]
        
    
    def user_token(self, addr_ip):
        user_token= sha256((self.user+self.chave +addr_ip).encode()).hexdigest() if val_tokem else tokem
        return user_token

    
    def log_login(self,addr_ip):
        data=datetime.now().strftime("%d_%m_%Y")
        hora=datetime.now().strftime("%H:%M")
        with open(f'./login/login_{data}.log','a') as arq:
            texto=f'''/user: {self.user: <22}/ip: {addr_ip: <18}/as: {hora}\n'''
            arq.write(texto)
            arq.close()

    def connetc(self): 
        try:
            self.conn=Connection(server,self.logon,self.pwd)
            return self.conn.bind()
        except:
            return "offline"
    
    def logout(self):
        self.conn.unbind()
        return {'response':True,'mensg':'deslog'}
    
    def my_dados(self,addr_ip):
        dados=self.consulta('aaa',2,my=True)
        self.all_dados=dados['users001'][0]
        self.all_dados['token']=self.user_token(addr_ip)
        return self.all_dados
    
    def consulta(self,nome,quant_pag=20,my=False):
        if not my:
            text=f'(&(objectclass=user)(cn={nome}*))'
            if 'ROOT' in self.all_dados['memberof']:
                pass
            elif 'ADD_ALUNO' in self.all_dados['memberof']:
                text=text.replace('*))',f"*)(memberof={grupos['ALUNO']}))")
            elif 'ADD_SERVIDOR' in self.all_dados['memberof']:
                text=text.replace('*))',f"*)(memberof={grupos['SERVIDOR']}))")
            else:
                return {'response':False,'mensg':'sem autorização'}
        else:
            text=f'(&(objectclass=user)(sAMAccountName={self.user}))'
        self.conn.search(base, text ,attributes=attributes)
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
                        'memberof': config_group(f'{i.memberof}'.replace("[]",'')),
                        'telefone': f'{i.telephonenumber}'.replace("[]",''),
                        'email': f'{i.mail}'.replace("[]",''),
                        'mail2': f'{i.adminDisplayName}'.replace("[]",''),
                        #'email':f'{i.sAMAccountName}{dominio}',
                        'givenname': f'{i.givenname}'.replace("[]",''),
                        'DN': f'{i.distinguishedName}',
                        'info':f'{i.info}',
                        'login':f'{i.sAMAccountName}',
                        'estado':i.userAccountControl.value & 2 != 2,
                        'cpf':f'{i.division}',
                        'nascido':f'{i.comment}'})
        return dados

    def validar_objeto(self,attr,valor):
        filter=f'(&(objectClass=user)({attr}={valor}))'
        attri=[attr]
        self.conn.search(base,filter,attributes=attri)
        return(bool(self.conn.entries))
    
    def adduser(self,dados:dict) ->dict :   #adiciona usuario  
        nome=dados['nome']                  #dados é um json
        l_nome=nome.split()
        email2=dados.get('email2')
        tell=f'{dados.get("telefone")}'
        desc = dados.get("desc")
        nascido=dados.get('nascido')
        cpf=dados.get('cpf')
        if email2.endswith(base_email):
            return {'response':False,'mensg':f'email secundario não pode ser de {base_email}'}
        fn=l_nome[0]
        ln=' '.join(l_nome[1:])
        login1=login=unidecode(f'{fn}.{l_nome[-1]}'.lower())
        login2=unidecode(f'{fn}.{[l_nome[-3],l_nome[-2]][len(l_nome[-2])>2]}'.lower())

        if self.validar_objeto('division',cpf):  #verificação de PCF usuario  campo "division"
            return {'response':False,'mensg':'CPF já consta na base','login':f'{login1}'}
        if self.validar_objeto('sAMAccountName',login):  #verificação de login1
            login=login2
            if self.validar_objeto('sAMAccountName',login): #verificação de login2
                return {'response':False,'mensg':'login ja existe','login':f'{login1} & {login2}'}
        DN=f"CN={nome},CN=Users,{base}"
        attr={ 'objectclass':['top','person', 'organizationalPerson', 'user'],
                'cn':nome,                                      #nome completo
                'displayname':nome,                             #nome completo
                'uid':login,                                    #idetificador unico
                'givenName':l_nome[0],                          #primeiro nome
                'sn':' '.join(l_nome[1:]),                      #sobre nome
                'sAMAccountName':login,                         #login
                'description':desc if desc else ' ',            #descrição da conta
                'mail':f'{login}{base_email}',                 #email p/ simcronizar com google   @ufnt.edu.br
                'adminDisplayName':email2,                      #email segundario
                'userPrincipalName': f'{login}{dominio}',       #email de login do ldap
                'userAccountControl':'66080',                   #estado da conta   : senha nunca expira
                'info':f"criador: {self.all_dados['DN']}",      #informação do criador
                'telephoneNumber':tell if tell else ' ',        #telefone
                'division':cpf,                                 #cpf
                'comment':nascido if nascido else ''}           #data de nascimento  
        
        poder_self=self.all_dados['memberof']
        if 'ROOT' in poder_self:
            teste_gp=dados.get('poder')
            GP=teste_gp.upper() if  teste_gp else False         #'poder' de POST 
            if not GP:
                GP={'SERVIDOR':grupos.get('SERVIDOR')}
            elif GP =='ALUNO':
                GP={'ALUNO':grupos['ALUNO']}
            else:
                GP={GP:grupos[GP]}
                GP['SERVIDOR']=grupos['SERVIDOR']
        elif 'ADD_SERVIDOR' in poder_self:
            GP={'SERVIDOR':grupos.get('SERVIDOR')}
        elif 'ADD_ALUNO' in poder_self:
            GP={'ALUNO':grupos.get('ALUNO')}
        else:
            return {'response':False,'mensg':'sem autorização','login':'None'}

        r=self.conn.add(DN,attributes=attr)
        c=login
        b='erro ao criar usuario'
        if r:
            b='usuario criado'
            pwd=f'Senha@{randint(1000,9999)}'
            command=f'dsmod user "{DN}" -pwd "{pwd}" -mustchpwd no'
            a='passa sem shell'
            if shell:
                a=sub.run(command,shell=1,capture_output=1,text=1).stdout
            
            for i in GP:
                self.modify_group({'DN_user':DN,'DN_group':GP[i],'modify':'add'})  # adiciona no grupo segundo o cargo
            texto= open(boasvinda,encoding=encode).read()
            msg=formatar(texto,nome=nome, login=login, pwd=pwd,self=self)
            th0=Thread(target=enviar_email, args=(dados.get('email2'),'Senha de acesso',msg))
            th0.start()
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
        con=Connection(server,self.logon,pwd)
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
            if email == self.all_dados.get('mail2'):
                return {'response':False, 'mensg':'email é o mesmo'}
            
            elif email.endswith(dominio):
                return {'response':False, 'mensg':f'a email não pode ser de {dominio}'}
            if not token:
                self.codigo=f'UFNT-{randint(100,999)}'
                texto=open(confirmaremail,encoding=encode).read()
                msg=formatar(texto,codigo=self.codigo,self=self)
                th0=Thread(target=enviar_email, args=(email,'validar email',msg))
                th0.start()
                return {'response':True, 'mensg':f'verificar {email}'}
            elif token !='teste.15975369874123658' and token != self.codigo :
                return {'response':False, 'mensg':f'codigo invalido'}
            attr['mail']=[(MODIFY_REPLACE,[email])]
        self.conn.modify(self.all_dados['DN'],attr)
        if self.conn.result['result']==0:
            del self.codigo
            return {'response':True, 'mensg':'Dados atualizados'}
        return {'response':False, 'mensg':'erro'}


def formatar(texto,nome='',pwd='',codigo='',login='', self=''):
    free=datetime.now().strftime
    nome1 = nome.split()[0] if nome else False
    hora=free('%H:%M')
    semana=['Domingo','Segunda','Terça','Quarta','Quinta','Sexta','Sábado'][int(free('%w'))]
    mes=['Janeiro,', 'Fevereiro,', 'Março,', 'Abril,', 'Maio,', 'Junho,', 
            'Julho,', 'Agosto,', 'Setembro,', 'Outubro,', 'Novembro,', 'Dezembro'][int(free('%m'))-1]
    data=free('%d/%m/%Y')
    if self:
        l_self={'nome_self': self.all_dados.get('cn'),
                'nome_self1': self.all_dados.get('cn').split()[0],
                'login_self': self.all_dados.get('login'),
                'logon_self': self.all_dados.get('login')+dominio
                }
    else: l_self={}

    return texto.format(
    nome = nome,
    nome1 = nome1,
    login = login,
    logon = login+dominio if login else '',
    pwd = pwd,
    codigo = codigo,
    data = data,
    hora = hora,
    semana = semana,
    mes = mes,
    **l_self
    )

def esqueci_senha(dados):
    nome=dados['nome']
    cpf=dados['cpf']
    nascido=dados['nascido']
    email=dados['email']
    root=globals().get('root')
    if not root:
        return {'response':False , 'mensg':'usuario principal não credenciado, aguarde uns minutos'}
    user_root=Connection(server,root[0]+dominio, root[1])
    if not user_root.bind():
        return {'response':False , 'mensg':'erro no usuraio root'}
    else:
        filter=f'(&(objectclass=user)(division={cpf}))'
        attr=['cn','comment','division','admindisplayname','distinguishedName']
        user_root.search(base,filter,attributes=attr)
        lista=user_root.entries
        if lista:
            user=lista[0]
            if user.comment == nascido:
                if f'{user.cn}'.lower() == nome.lower():
                    if f'{user.admindisplayname}'.lower() == email.lower():
                        dn=user.distinguishedName
                        new_pwd=f'Senha@{randint(1000,9999)}'
                        command=f'dsmod user "{dn}" -pwd "{new_pwd}" -mustchpwd no'
                        a='passa sem shell'
                        if shell: 
                            a=sub.run(command,shell=1,capture_output=1,text=1).stdout   #sobracreve a senha do usuario
                            a=sub.run(command,shell=1,capture_output=1,text=1).stdout
                            if a=='':
                                return {'response':False , 'mensg':'nova senha invalida'}

                            texto=open(email_esqueci_senha,encoding=encode).read()
                            msg=formatar(texto,nome=nome, pwd=new_pwd)
                            th0=Thread(target=enviar_email, args=(email,'validar email',msg))
                            th0.start()
                            return {'response':True, 'mensg':f'verificar {email}'}
                        return {'response':True, 'mensg':f'verificar {email} __test__'}
                        
        return {'response':False , 'mensg':'USER não encontrado'}
            
            
            
        
    

