import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from json import loads


server='smtp.gmail.com'
port=587

conf=loads(open('config.ini').read())
email=conf['conf_email']['EMAIL']
pwd=conf['conf_email']['KEY_APP']
roda_pe=conf['conf_email']['FILE_RODAPE']
encode=conf.get('conf_email').get('ENCODE')

roda_pe=open(roda_pe,encoding=encode).read()


html='''
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8"></head>
<body>
    <div>
    {texto}
    </div>
<br> <br> <br>
{roda_pe}

</body>
</html>
    '''


def enviar_email(destino,assunto,texto):
    msg=MIMEMultipart()
    msg['From']=email
    msg['To']=destino
    msg['Subject']=assunto

    texto=html.format(texto=texto, roda_pe=roda_pe)

    msg.attach(MIMEText(texto,'html', _charset='utf-8'))
    servidor=smtplib.SMTP(server,port)
    servidor.starttls()
    servidor.login(email,pwd)
    a=servidor.sendmail(email, destino, msg.as_string())
    servidor.quit()






