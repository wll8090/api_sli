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


erro404 = lambda: abort(404)
r=['login','users','adduser','groups' ,'add_group', 'modify_group', 'delete_user', 'delete_group',
    'reset_pwd', 'user_pwd',              'logout']

ldap_usrs={}

## erro de tokem ou login
msgerro={'response':'Tokenize error & user login'}


def rotas(seg):
    s=f'/{seg}/<user>/'
    for i in r[1:]:
        yield s+i

def deslog(app):
    for i in r:
        app.view_functions[i]=erro404
    return None

def limpar_rotas(app):
    for i in r:
        app.view_functions.pop(i)
    return True


def logon(user,pwd):
    global ldap_usrs
    user_l=user_ldap(user,pwd)
    if user_l.connetc():
        ldap_usrs[user]=user_l
        return user
    else: return False 


def validar_tokem(func):
    @wraps(func)
    def new_func(user):
        tt=request.headers.get('Authorization')
        tokem=dict([tt.split(' ') if tt else ['a','b']])
        bearer=tokem.get('Bearer')
        if not val_tokem and user in ldap_usrs:   ##  <<--- passa tudo (tokem)
            return func(user)
        if user not in ldap_usrs or not bearer:
            return jsonify(msgerro)
        if ldap_usrs[user].userID==bearer:
            return func(user)
        return jsonify(msgerro)
    return new_func


def assinar():
    assina=datetime.now().strftime("%d/%m-assinado-%d/%m")
    dia=datetime.now().strftime("%d/%m-bolinha-%d/%m")
    cript_dia=sha256(dia.encode('utf8')).hexdigest()
    if liberado:
        assina ='25/07-assinado-25/07'
        cript_dia='0f7b8c3893290e18eaec7c09d7d794d13a83b79ab68bc3a5c228650ee87ff85f'
    assinado=sha256((cript_dia+assina).encode('utf8')).hexdigest()
    return cript_dia , assinado

#################### paginas com autenticação ###############

def pages(app,seg):
    if r[0] in app.view_functions:
        limpar_rotas(app)
    rr=rotas(seg)

    @app.route(next(rr),methods=['get']) ##  /users   --> pesquisa por usuario
    @validar_tokem
    def users(user):
        letra=request.args.get("chr")           #letra da requisição
        n=request.args.get("pag")               #numero da pagina
        quant_pag=request.args.get("qp")        #quantidade por pagina  *20
        n=int(n) if n != None else 1
        quant_pag=int(quant_pag) if quant_pag !=None else 20 
        pg=f'users{n:0>3}'
        req=ldap_usrs[user].consulta(letra,quant_pag)
        dados={'users':req.get(pg),
                'total_pg':len(req),
                'atual_pg':n}
        return jsonify(dados)


    @app.route(next(rr),methods=['POST'])  ## /adduser   --> adiciona usuario
    @validar_tokem
    def adduser(user):
        dados=json.loads(request.data)
        r=ldap_usrs[user].adduser(dados)
        if r:
            return r
        return jsonify({"response":"end_function"}) 

    
    @app.route(next(rr),methods=['GET'])  ## /groups   --> pesquisa grupos
    @validar_tokem
    def groups(user):
        letra=request.args.get("chr")           #letra da requisição
        n=request.args.get("pag")               #numero da pagina
        quant_pag=request.args.get("qp")        #quantidade por pagina  *20
        membros=request.args.get("membros")     #deve listar os membros *0
        n=int(n) if n != None else 1
        quant_pag =int(quant_pag) if quant_pag !=None else 20 
        membros= int(membros) if membros !=None else 20
        pg=f'group{n:0>3}'
        req=ldap_usrs[user].consulta_group(letra,quant_pag,membros)
        dados={'groups':req.get(pg),
                'total_pg':len(req),
                'atual_pg':n}
        return jsonify(dados)


    @app.route(next(rr),methods=['POST'])   ## /add_group  -->adiciona grupo
    @validar_tokem
    def add_group(user):
        dados=json.loads(request.data)
        r=ldap_usrs[user].creat_group(dados)
        return jsonify({'response':[False,True][r]})


    @app.route(next(rr),methods=['POST'])   ## /modify_group   --> adiciona e remove de grupo
    @validar_tokem
    def modify_group(user):
        dados=json.loads(request.data)
        r=ldap_usrs[user].modify_group(dados)
        return jsonify({'response':r})
    

    @app.route(next(rr),methods=['POST'])   ## /delete_user   --> delete usuario
    @validar_tokem
    def delete_user(user):
        dados=json.loads(request.data)
        r=ldap_usrs[user].rm_user(dados)
        return jsonify({'response':r})

    
    @app.route(next(rr),methods=['POST'])   ## /delete_goup   --> delete grupo
    @validar_tokem
    def delete_group(user):
        dados=json.loads(request.data)
        r=ldap_usrs[user].rm_group(dados)
        return jsonify({'response':r})
    

    @app.route(next(rr),methods=['POST'])   ## /reset_pwd --> trocar senha do usuario    
    @validar_tokem
    def reset_pwd(user):
        dados=json.loads(request.data)
        r=ldap_usrs[user].troca_senha(dados)
        return jsonify({'response':r})
    

    @app.route(next(rr),methods=['POST'])   ## /user_pwd --> trocar senha de outros usuario   
    @validar_tokem
    def user_pwd(user):
        dados=json.loads(request.data)
        r=ldap_usrs[user].user_senha(dados)
        return jsonify({'response':r})


    #--------------------- end ---------
    @app.route(next(rr),methods=['GET'])   ## /logout     --> desloga user
    @validar_tokem
    def logout(user):
        aa=ldap_usrs.pop(user)
        aa.logout()
        del(aa)
        return f'{user} logout'


    @app.route(f'/{seg}/{r[0]}',methods=['POST']) ## /login   --> loga usuario
    def login():
        dados=json.loads(request.data)
        r_user=logon(**dados)
        if r_user:
            dd=ldap_usrs[r_user].my_dados()
            ldap_usrs[r_user].log_login()
            return jsonify(dd)
        return abort(400)


#################--------##################################

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
        global assinado, seg, cript , ldap_usrs
        cript,assinado=assinar()
        seg=assinado[-20:-10]
        if chave==cript:
            pages(app,seg)
            return jsonify({'get':cript,'signed':assinado})
        elif chave=='000':
            if r[0] in app.view_functions:
                deslog(app)
            ldap_usrs={}
            return f'deslogin ok '
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
            {texte}
            '''


    @app.route('/doc')   ## --> documentação da API
    def doc():
        return render_template('doc.html')
    app.run(host=host,port=port)


######### app   ----------------------  ######
if __name__ == '__main__':
    main()
