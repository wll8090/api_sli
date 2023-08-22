from flask import Flask ,abort, jsonify, request, make_response,render_template
from hashlib import sha256
from datetime import datetime
from flask_cors import CORS
from clildap import user_ldap
from datetime import datetime, timedelta
from functools import wraps

import json
import logging

with open('config.ini') as arq:
    conf=json.loads(arq.read())
    arq.close()

port=conf.get('init').get('PORT')
host=conf.get('init').get('HOST')
ipCORS=conf.get('init').get('IPCORS')
logs=conf.get('testes').get('LOGS')
liberado=conf.get('testes').get('LIBERADO')
val_tokem=conf.get('testes').get('VAL_TOKEM')

ldap_usrs={}
erro404 = lambda: abort(404)
api_assinada=False

## erro de tokem ou login
msgerro={'response':'Tokenize error & user login'}

def logon(dados):
    global ldap_usrs
    user=dados['user']
    pwd=dados['pwd']
    user_l=user_ldap(user,pwd)
    if user_l.connetc():
        ldap_usrs[user]=user_l
        return user_l.my_dados()
    else: return {'resmpose':False} 


def validar_tokem(func):
    @wraps(func)
    def new_func(user,acao):
        tt=request.headers.get('Authorization')
        tokem=dict([tt.split(' ') if tt else ['a','b']])
        bearer=tokem.get('Bearer')
        if not val_tokem and user in ldap_usrs:   ##  <<--- passa tudo (tokem)
            return func(user,acao)
        if user not in ldap_usrs or not bearer:
            return jsonify(msgerro)
        if ldap_usrs[user].userID==bearer:
            return func(user,acao)
        return jsonify(msgerro)
    return new_func


def validar_api(func):
    @wraps(func)
    def new_funtion(user='',acao=''):
        if not api_assinada:
            return erro404()
        if user: return func(user,acao)
        else: return func()
    return new_funtion



def assinar():
    assina=datetime.now().strftime("%d/%m-assinado-%d/%m")
    dia=datetime.now().strftime("%d/%m-bolinha-%d/%m")
    cript_dia=sha256(dia.encode('utf8')).hexdigest()
    if liberado:
        assina ='25/07-assinado-25/07'
        cript_dia='0f7b8c3893290e18eaec7c09d7d794d13a83b79ab68bc3a5c228650ee87ff85f'
    assinado=sha256((cript_dia+assina).encode('utf8')).hexdigest()
    return cript_dia , assinado


def users(user,args):
    letra=args.get("chr")           #letra da requisição
    n=args.get("pag")               #numero da pagina
    quant_pag=args.get("qp")        #quantidade por pagina  *20
    n=int(n) if n != None else 1
    quant_pag=int(quant_pag) if quant_pag !=None else 20 
    pg=f'users{n:0>3}'
    req=ldap_usrs[user].consulta(letra,quant_pag)
    dados={'users':req.get(pg),
            'total_pg':len(req),
            'atual_pg':n}
    return dados

def groups(user,args):
    letra=args.get("chr")           #letra da requisição
    n=args.get("pag")               #numero da pagina
    quant_pag=args.get("qp")        #quantidade por pagina  *20
    membros=args.get("membros")     #deve listar os membros *0
    n=int(n) if n != None else 1
    quant_pag =int(quant_pag) if quant_pag !=None else 20 
    membros= int(membros) if membros !=None else 20
    pg=f'group{n:0>3}'
    req=ldap_usrs[user].consulta_group(letra,quant_pag,membros)
    dados={'groups':req.get(pg),
            'total_pg':len(req),
            'atual_pg':n}
    return dados

#################### paginas com autenticação ###############
def rotas_fechadas(app,seg):
    if 'rotas_ocutas' in app.view_functions: return True

    @app.route(f'/{seg}/login/',methods=['post'])
    @validar_api
    def login():
        dados=json.loads(request.data)
        re=logon(dados)
        return jsonify(re)


    @app.route(f'/{seg}/<user>/<acao>/',methods=['GET','POST'])
    @validar_api
    @validar_tokem
    def rotas_ocutas(user,acao):
        re='nada'
        if request.method == 'GET':   #todos os GETS
            args=request.args
            if acao == 'users':             #fas pesquisas de usuarios
                re=users(user,args)
            elif acao == 'groups':          #faz pesquisas de grupos
                re=groups(user,args)
            elif acao == 'logout':          #desloga o usuario
                aa=ldap_usrs.pop(user)
                aa.logout()
                del(aa)
                re={'response':True}

        elif request.method=='POST':   #todos os POSTS
            dados=json.loads(request.data)
            if acao=='add_user':                        #adiniona novo usuario
                re=ldap_usrs[user].adduser(dados)
            elif acao == 'add_group':                   #adiciona novo grupo 
                re=ldap_usrs[user].creat_group(dados)
            elif acao == 'modify_group':                #modifica grupo adicionae remove usuarios
                re=ldap_usrs[user].modify_group(dados)
            elif acao == 'delete_user':                 #deleta usuario
                re=ldap_usrs[user].rm_user(dados)
            elif acao == 'delete_group':                #deleta grupos
                re=ldap_usrs[user].rm_group(dados)
            elif acao == 'reset_pwd':                   #troca senha do self.usuario
                re=ldap_usrs[user].troca_senha(dados)
            elif acao == 'user_pwd':                    #troca senha de outros usuarios
                re=ldap_usrs[user].user_senha(dados)
        if re=='nada': return erro404()
        return jsonify(re)

####################################################################

def main():
    app=Flask(__name__)

    @app.before_request
    def before():
        CORS(app,restore={r"/*":{"origins":f"http://{ipCORS}" , "supports_credentials":True ,  "headers": ["Authorization"]}})

    data=datetime.now().strftime('%d_%m_%Y')
    log_formatter = logging.Formatter('-'*100+'\n<hr>%(asctime)s - %(levelname)s - %(message)s -')
    file_handler = logging.FileHandler(f'logs/erro_{data}.log')
    file_handler.setFormatter(log_formatter)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.ERROR)


    @app.route('/login/<chave>')      ## -->  loga na API
    def index(chave):
        global assinado, seg, cript , ldap_usrs, api_assinada
        cript,assinado=assinar()
        seg=assinado[-20:-10]
        if chave==cript:
            api_assinada=True
            rotas_fechadas(app,seg)
            return jsonify({'get':cript,'signed':assinado})
        elif chave=='000':
            api_assinada=False
            ldap_usrs={}
            return jsonify({'response':'True','msg':'API logout'})
        else:
            return jsonify({'get':'None','signed':'None'})
        
    if logs:
        @app.route('/log')
        def log():
            cript,assinado=assinar()
            seg=assinado[-20:-10]
            texte=open(f'logs/erro_{data}.log').read()
            return f'''get: {cript} <br>
            assinado: {assinado} <br>
            rota :{seg}
            <hr> 
            ldap_users: {ldap_usrs}<hr>
            rotas: {app.view_functions} <hr>
            {texte}'''

    @app.route('/doc')   ## --> documentação da API
    def doc():
        return render_template('doc.html')
    app.run(host=host,port=port)

    @app.route(f'/{seg}/login',methods=['POST']) ## /login   --> loga usuario
    def login():
        if not api_assinada:
            return erro404()
        dados=json.loads(request.data)
        r_user=logon(**dados)
        if r_user:
            dd=ldap_usrs[r_user].my_dados()
            ldap_usrs[r_user].log_login()
            return jsonify(dd)
        return abort(400)

######### app   ----------------------  ######
if __name__ == '__main__':
    main()
