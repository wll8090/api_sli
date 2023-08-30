from json import loads
from datetime import datetime
from hashlib import sha256
from time import sleep

import requests


##########################################################
#       TESTE DE API  V 0.0.1
#       escolha as opções quie teste a segui  
#       mode para True ou False 
#
##########################################################


login_app=True             #para testar o login na API
login_logout_user=True     #para testar o login do user
teste_de_alter_dados=True  #para testar modificar email2 e telefone
pesquisar_usuario=False     #para testar pesquisar por usuarios
pesquisar_grupos=False      #para testar pesquisar por grupos
add_rm_usuario=True        #para testar criar e pagar usuario
add_rm_grupo=False          #para testar criar e apagar grupo
senha_self=False            #para testar trocar senha do proprio usuario
senha_users=False            #para testar trocar a senha de outros usuarios
mecher_no_grupo=False       #para testar adicionar e remover usuarios de grupo



login_app=login_app|login_logout_user|add_rm_usuario|add_rm_grupo|senha_self|senha_users|mecher_no_grupo|pesquisar_usuario|pesquisar_grupos
login_logout_user=login_logout_user|add_rm_usuario|add_rm_grupo|senha_self|senha_users|mecher_no_grupo|pesquisar_usuario|pesquisar_grupos



with open('./config.ini','r') as arq:
    dados=loads(arq.read())


host=dados['init']['HOST']
port=dados['init']['PORT']
flag=dados['init']['FLAG']

rota=f'http://{host}:5001'

login={"user":"user.root","pwd":"@Aa1020"}


def decora(msg):
    def new_func(func):
        def funcao(dados):
            print(f'\n**** Teste de: {msg} ****')
            
            re,ree,dados =func(dados)
            print(re,'---------------------')
            if  re:
                print(f'OK:{ree}')
            else: 
                print(f'error em :{msg} -->{ree}')
                print('^'*30)
                quit() 
            print('-'*30,'\n\n')
            sleep(1)
            return re,dados
        return funcao
    return new_func



def authenticar():
    assina=datetime.now().strftime("%d/%m-assinado-%d/%m")
    dia=datetime.now().strftime(f"%d/%m-{flag}-%d/%m")
    cript_dia=sha256(dia.encode('utf8')).hexdigest()
    assinado=sha256((cript_dia+assina).encode('utf8')).hexdigest()
    rota=assinado[-20:-10]
    dd= {'assinado':assinado, 'cripto_do_dia':cript_dia,'rota':rota}
    print(dd)
    return dd


@decora('atenticação na api')
def teste_init_api(dados):
    a=loads(requests.get(f'{rota}/login/{dados["cripto_do_dia"]}').text)
    re=a['signed']==dados['assinado']
    return re,'passou!', None

@decora('login de usuario')
def teste_login_user(login):
    print(chave)
    re=requests.post(f"{rota}/{chave}/login/swswsw",json=login).text
    print(re)
    re=loads(re)
    return (re['sAMAccountName'] == login['user']) , 'passou!' , re


@decora('pesquisa de usuario&grupo')
def teste_de_pesquisa(dados):
    print(f'****{dados}')
    r=f"{rota}/{chave}/{user}/{pesquisar}"
    re=loads(requests.get(r,headers=head).text)
    return re.get('atual_pg')==1, 'passou!', None

@decora('logout de usuario')
def teste_de_deslog_de_usuario(dados):
    print(f'****{dados}')
    r=f"{rota}/{chave}/{user}/logout"
    re=loads(requests.get(r,headers=head).text)
    return re['response'], 'passou!', None


@decora('rota de endpoint')
def teste_endpoint(dados):
    print(f'****-->{dados["end"]}')
    r=f"{rota}/{chave}/{user}/{dados['end']}"
    print(f'Em: {r}')
    re=loads(requests.post(r, json=dados['dd'], headers=head).text)
    return re['response'] , re['mensg'] , None

#########################################################


dados=authenticar()
chave=dados['rota']

##### iniciação da API
if login_app:
    teste_init_api(dados)



##### login de usuario
if login_logout_user:
    re,dados_user=teste_login_user(login)
    token=dados_user['token']
    user=dados_user['sAMAccountName']
    head={"Authorization":f'Bearer {token}','Content-Type': 'application/json'}

##### pesquisar por grupos
if pesquisar_grupos:
    pesquisar='groups?chr=grupo de&pag=1&qp=3&membros=1'
    teste_de_pesquisa('grupo')


##### adicionar usuario
if add_rm_usuario:
    nome="maria jose pereira marthins"
    dados={'end':'add_user',
            'dd':{   "nome":nome,
                    "pwd":"@Aa1020",
                    "email2":"williams.ferreira@mail.uft.edu.br",
                    "desc":"usuario de teste"}}
    teste_endpoint(dados)


##### trocar senha do usuario
if senha_users:
    dados={'end':'user_pwd',
        'dd':{   "DN":f"CN={nome},CN=Users,DC=ufnt,DC=local",
                    "new_pwd":dados['dd']['pwd']}}
    teste_endpoint(dados)


##### pesquisa de usuario
if pesquisar_usuario:
    pesquisar='users?chr=maria&pag=1&p=20'
    teste_de_pesquisa('usuario')


##### adicionar grupo
if add_rm_grupo:
    grupo="grupo de batata"
    dados={'end':'add_group',
        'dd':{   "nome":grupo,
                    "desc":"os membros podem criar apenas alunos"}}
    teste_endpoint(dados)


#####  modificar  grupo add user
if mecher_no_grupo:
    dados={ 'end':'modify_group',
            'dd':{  "DN_user":f"CN={nome},CN=Users,DC=ufnt,DC=local",
                    "DN_group":f"CN={grupo},CN=Users,DC=ufnt,DC=local",
                    "modify":"add" }}
    teste_endpoint(dados)

##### modificar  grupo remove user
if mecher_no_grupo:
    dados['dd']['modify']='remove'
    teste_endpoint(dados)


##### apagar grupo
if add_rm_grupo:
    dados={'end':'delete_group',
        'dd':{"DN":f"CN={grupo},CN=Users,DC=ufnt,DC=local"}}
    teste_endpoint(dados)

##### remover usuario
if add_rm_usuario:
    dados={'end':'delete_user',
        'dd':{"DN":f"CN={nome},CN=Users,DC=ufnt,DC=local"}}
    teste_endpoint(dados)

##### trocar a senha
if senha_self:
    dados={'end':'reset_pwd',
        'dd':{   "pwd":login['pwd'],
                    "new_pwd":login['pwd']}}
    teste_endpoint(dados)



##### mudar os dados telefone e email e validar email
if teste_de_alter_dados:
    dados={'end':'alter_count',
        'dd':{'tell':'91980808184',
           'email':'williams.ferreira@mail.uft.edu.br'}}
    teste_endpoint(dados)
    print('*****validar TOKEN*****')
    dados['dd']['token']='teste.15975369874123658'
    teste_endpoint(dados)


###### logout de ususario
if login_logout_user:
    teste_de_deslog_de_usuario('logout')
