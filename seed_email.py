import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from json import loads


server='10.253.251.37'
port=587


conf=loads(open('config.ini').read())
user=conf['conf_email']['USER']
pwd=conf['conf_email']['PWD']
roda_pe=conf['conf_email']['FILE_RODAPE']
encode=conf.get('conf_email').get('ENCODE')

roda_pe=open(roda_pe,encoding=encode).read()


html='''
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="{encode}"></head>
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
    msg['From']=user
    msg['To']=destino
    msg['Subject']=assunto

    texto=html.format(texto=texto, roda_pe=roda_pe,encode=encode)

    msg.attach(MIMEText(texto,'html', _charset=encode))
    servidor=smtplib.SMTP(server,port)
    #servidor.starttls()
    servidor.login(user,pwd)
    a=servidor.sendmail(user, destino, msg.as_string())
    servidor.quit()
