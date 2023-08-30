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

roda_pe=open(roda_pe,encoding='utf8').read()

hora=datetime.now().strftime("%H:%M  %d/%m/%Y")

def enviar_email(destino,assunto,texto):

    msg=MIMEMultipart()
    msg['From']=email
    msg['To']=destino
    msg['Subject']=assunto

    html=f'''
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8"></head>
<body>
    <div>
    {texto}
    </div>
em: {hora}
<br> <br> <br>
{roda_pe}

</body>
</html>
    '''

    msg.attach(MIMEText(html,'html', _charset='utf-8'))
    servidor=smtplib.SMTP(server,port)
    servidor.starttls()
    servidor.login(email,pwd)
    servidor.sendmail(email, destino, msg.as_string())
    servidor.quit()











