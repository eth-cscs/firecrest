FROM python:3.7-alpine
ADD ./requirements.txt requirements.txt
RUN pip install -r requirements.txt

ADD ./ app

WORKDIR app

EXPOSE 7000

ENTRYPOINT ["python", "firecrest_demo.py"]
