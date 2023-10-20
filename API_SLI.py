from apscheduler.schedulers.background import BackgroundScheduler
from clildap import user_ldap , esqueci_senha
from datetime import datetime
from flask import Flask ,abort, jsonify, request
from flask_cors import CORS, cross_origin 
from hashlib import sha256
from threading import Thread
from jinja2 import Template

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
flag=conf.get('init').get('FLAG')
encode=conf.get('conf_email').get('ENCODE')
hora,minuto=[int(i) for i in conf.get('init').get('HORA').split(':')]


ldap_usrs={}
erro404 = lambda: abort(404)
api_assinada=False

## erro de tokem ou login
msgerro={'response':'Tokenize error & user login'}

def logon(dados,addr_ip):
    global ldap_usrs
    user=dados['user']
    pwd=dados['pwd']
    user_l=user_ldap(user,pwd)
    if user_l.connetc():
        ldap_usrs[user]=user_l
        user_l.log_login(addr_ip)
        dd=user_l.my_dados(addr_ip)
        return dd
    else: return {'resmpose':False,'mensg':'usuario ou senha incorreto'} 

def assinar():
    global cript,assinado
    assina=datetime.now().strftime("%d/%m-assinado-%d/%m")
    dia=datetime.now().strftime(f"%d/%m-{flag}-%d/%m")
    cript=sha256(dia.encode('utf8')).hexdigest()
    if liberado:
        assina ='25/07-assinado-25/07'
        cript='0f7b8c3893290e18eaec7c09d7d794d13a83b79ab68bc3a5c228650ee87ff85f'
    assinado=sha256((cript+assina).encode('utf8')).hexdigest()
    return cript , assinado


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


def reset_api():
    global api_assinada, ldap_usrs
    api_assinada=False
    ldap_usrs={}
    print(f'------- reset_api --> {hora}:{minuto}--------')
    return True

#################### paginas com autenticação ###############
def rotas_fechadas(app):
    if 'rotas_ocutas' in app.view_functions: 
        return True

    @app.route('/<rota_seg>/<user>/<acao>',methods=['GET','POST'])
    @cross_origin()
    def rotasocultas(rota_seg,user,acao):
        

        addr_ip= request.remote_addr
        if not api_assinada or rota_seg != seg:
            return erro404()
        if user != 'login' and user != 'req_senha':
            tt=request.headers.get('Authorization')
            tokem=dict([tt.split(' ') if tt else ['a','b']])
            bearer=tokem.get('Bearer')
            if user not in ldap_usrs or not bearer:
                return jsonify(msgerro)
            if ldap_usrs[user].user_token(addr_ip) != bearer:
                return jsonify(msgerro)

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
            print(dados)
            if user=='login':
                re=logon(dados,addr_ip)
            elif acao=='add_user':                      #adiniona novo usuario
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
            elif acao == 'alter_count':                 #troca o telefone e email do self.usuario
                re=ldap_usrs[user].modify_my_count(dados)
            if acao == 'esqueci_senha':               # rota para esqueci a senha
                re=esqueci_senha(dados)
                
        
        if re=='nada': return erro404()
        return jsonify(re)


####################################################################

def main():
    app=Flask(__name__)

    
    #CORS(app,restore={r"/*":{"origins":f"http://{ipCORS}" , "supports_credentials":True ,  "headers": ["Authorization"]}})

    data=datetime.now().strftime('%d_%m_%Y')
    log_formatter = logging.Formatter('-'*100+'\n<hr>%(asctime)s - %(levelname)s - %(message)s -')
    file_handler = logging.FileHandler(f'logs/erro_{data}.log')
    file_handler.setFormatter(log_formatter)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.ERROR)


    rotas_fechadas(app)
    print(ipCORS)

    @app.route('/login/<chave>')      ## -->  loga na API
    @cross_origin()
    def index(chave):
        global seg, api_assinada
        assinar()
        if chave==cript:
            seg=assinado[-20:-10]
            api_assinada=True
            return jsonify({'get':cript,'signed':assinado})
        else:
            return jsonify({'get':'None','signed':'None'})
    
        
    if logs:
        @app.route('/log')
        def log():
            ip=request.remote_addr
            assina=datetime.now().strftime("%d/%m-assinado-%d/%m")
            dia=datetime.now().strftime(f"%d/%m-{flag}-%d/%m")
            cript=sha256(dia.encode('utf8')).hexdigest()
            if liberado:
                assina ='25/07-assinado-25/07'
                cript='0f7b8c3893290e18eaec7c09d7d794d13a83b79ab68bc3a5c228650ee87ff85f'
            assinado=sha256((cript+assina).encode('utf8')).hexdigest()
            seg=assinado[-20:-10]
            all_user={i:ldap_usrs[i].user_token(ip) for i in ldap_usrs}
            texte=open(f'logs/erro_{data}.log').read()
            return f'''get: {cript} <br>
            assinado: {assinado} <br>
            rota :{seg}
            <hr> 
            ldap_users: {all_user}<hr>
            rotas: {app.view_functions} <hr>
            {texte}'''

    @app.route('/doc')   ## --> documentação da API
    def doc():
        doc=Template(open('./templates/doc.html',encoding=encode).read()).render()
        return doc
    
    app.run(host=host,port=port)

######### app   ----------------------  ######
if __name__ == '__main__':
    sched=BackgroundScheduler()
    sched.add_job(reset_api, 'cron',hour=hora, minute=minuto)
    th01=Thread(target=sched.start,daemon=1)
    th01.start()
    main()
