FROM python:3.7-alpine

RUN pip install flask flask-WTF flask-bootstrap flask-oidc flask_sslify requests

ADD ./ app

WORKDIR app

EXPOSE 5000

ENTRYPOINT ["python", "firecrest_demo.py"]
