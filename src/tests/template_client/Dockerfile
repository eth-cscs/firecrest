FROM python:3.7-alpine

ADD ./ app

WORKDIR app
RUN pip install -r requirements.txt

EXPOSE 5000

ENTRYPOINT ["python", "firecrest_demo.py"]
