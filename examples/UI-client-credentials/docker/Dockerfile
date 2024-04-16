FROM python:3.10-alpine

RUN apk add --no-cache gcc libc-dev libffi-dev

ADD ./docker/requirements.txt /app/docker/requirements.txt

RUN pip install -r /app/docker/requirements.txt

ADD ./ app
WORKDIR app


EXPOSE 9090

ENTRYPOINT ["python", "src/client.py"]