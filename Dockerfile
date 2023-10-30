FROM python:3

WORKDIR /main

RUN python3 -m pip install --upgrade pip
RUN pip install flask
RUN pip install ldap3
RUN pip install flask_cors
RUN pip install apscheduler
RUN pip install unidecode
RUN pip install requests
RUN pip install cryptography
RUN mkdir main


EXPOSE 5001/tcp

CMD ["python3","/main/API_SLI.py"]
